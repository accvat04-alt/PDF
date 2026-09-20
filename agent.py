"""
Agent ký số PDF bằng USB token (PKCS#11).

- Chạy trên máy có cắm token, chỉ lắng nghe ở 127.0.0.1.
- Phục vụ giao diện web (index.html) và 2 API:
    GET  /api/status   kiểm tra agent
    GET  /api/certs    liệt kê chứng thư số trên token (không cần PIN)
    POST /api/sign     ký PDF (chuẩn PAdES) bằng khóa riêng trong token
- PIN chỉ đi từ trình duyệt tới agent trên cùng máy, không được lưu.
"""
import io
import json
import os
import sys
import threading
import time
import traceback
import unicodedata
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, abort, jsonify, request, send_file, send_from_directory

FROZEN = getattr(sys, "frozen", False)  # True khi chạy từ file .exe (PyInstaller)
RES_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))  # nơi chứa index.html
APP_DIR = Path(sys.executable).resolve().parent if FROZEN else Path(__file__).resolve().parent  # nơi chứa config.json

DEFAULT_CONFIG = {
    "pkcs11_lib": "auto",
    "port": 8765,
    "font_path": "C:\\Windows\\Fonts\\arial.ttf",
    "timestamp_url": "",
    "use_raw_mechanism": False,
    "allowed_origins": [],
    "open_browser": True,
    "open_url": "",
}

# Tên DLL PKCS#11 thường gặp của token ở Việt Nam (tự dò khi pkcs11_lib = "auto")
LIB_CANDIDATES = [
    "eTPKCS11.dll",
    "eps2003csp11.dll",
    "viettel-ca_v6.dll",
    "vnpt-ca_csp11.dll",
    "vnptca_p11_v8.dll",
    "SignatureP11.dll",
    "ngp11v211.dll",
]
# Các DLL của Windows có chữ "p11" trong tên nhưng không phải driver token
SKIP_PREFIXES = ("msvcp", "vcamp", "vcomp")


def load_config():
    path = APP_DIR / "config.json"
    if not path.exists():
        path.write_text(json.dumps(DEFAULT_CONFIG, indent=2, ensure_ascii=False), encoding="utf-8")
    return {**DEFAULT_CONFIG, **json.loads(path.read_text(encoding="utf-8"))}


def _exports_pkcs11(path):
    """DLL có hàm C_GetFunctionList (dấu hiệu của driver PKCS#11) không? Chỉ dùng trên Windows."""
    if os.name != "nt":
        return True
    try:
        import ctypes

        return hasattr(ctypes.WinDLL(path), "C_GetFunctionList")
    except Exception:  # noqa: BLE001
        return False


def find_libs():
    """Mọi DLL PKCS#11 tìm thấy trong thư mục hệ thống (tên quen thuộc trước, rồi tự dò thêm)."""
    root = os.environ.get("SystemRoot", "C:\\Windows")
    found, seen = [], set()

    def add(path):
        key = str(path).lower()
        if key not in seen:
            seen.add(key)
            found.append(str(path))

    for folder in (Path(root) / "System32", Path(root) / "SysWOW64"):
        if not folder.is_dir():
            continue
        for name in LIB_CANDIDATES:
            if (folder / name).exists():
                add(folder / name)
        for pattern in ("*pkcs11*.dll", "*p11*.dll", "*csp11*.dll"):
            for path in sorted(folder.glob(pattern)):
                low = path.name.lower()
                if low.startswith(SKIP_PREFIXES) or low.endswith("_s.dll"):
                    continue
                if str(path).lower() not in seen and _exports_pkcs11(str(path)):
                    add(path)
    return found


def resolve_lib(value):
    if value and str(value).lower() != "auto":
        return value
    libs = find_libs()
    return libs[0] if libs else ""


def candidate_paths():
    """Danh sách DLL sẽ thử: đúng file trong config.json, hoặc mọi DLL dò được khi để auto."""
    value = str(CONFIG.get("pkcs11_lib", "auto") or "auto")
    return [value] if value.lower() != "auto" else find_libs()


CONFIG = load_config()
PORT = int(CONFIG["port"])
LIB_PATH = resolve_lib(CONFIG.get("pkcs11_lib", "auto"))

HOSTS = {f"127.0.0.1:{PORT}", f"localhost:{PORT}"}
ORIGINS = {f"http://{h}" for h in HOSTS} | set(CONFIG.get("allowed_origins", []))

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024


class AgentError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


@app.errorhandler(AgentError)
def handle_agent_error(e):
    return jsonify(error=str(e)), e.status


@app.errorhandler(Exception)
def handle_any_error(e):
    """Mọi lỗi khác đều trả về JSON để giao diện hiện đúng nguyên nhân."""
    from werkzeug.exceptions import HTTPException

    if isinstance(e, HTTPException):
        return jsonify(error=f"{e.code} {e.name}"), e.code
    traceback.print_exc()  # in chi tiết ra cửa sổ agent
    return jsonify(error=f"Lỗi trong agent: {type(e).__name__}: {e}"), 500


# ---------------------------------------------------------------- bảo mật cơ bản
@app.before_request
def guard():
    # Chặn DNS-rebinding: chỉ nhận Host là localhost/127.0.0.1
    if request.host not in HOSTS:
        abort(403)
    # Chặn trang web lạ gọi agent
    origin = request.headers.get("Origin")
    if origin and origin not in ORIGINS:
        abort(403)
    if request.method == "OPTIONS":
        return ("", 204)


@app.after_request
def add_cors(resp):
    origin = request.headers.get("Origin")
    if origin in ORIGINS:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        resp.headers["Access-Control-Allow-Private-Network"] = "true"
        resp.headers["Vary"] = "Origin"
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ---------------------------------------------------------------- PKCS#11
LAST_PROBE = []  # kết quả lần dò gần nhất, hiện trong "Kiểm tra kết nối token"


def _err_text(e):
    return f"{type(e).__name__}: {e}".rstrip(": ")


def enumerate_tokens(lib):
    """Liệt kê mọi token driver báo. Trả về (danh sách (slot, token), ghi chú, số khe đọc).
    Không nuốt lỗi: khe đọc nào không lấy được token sẽ có một dòng ghi lý do."""
    try:
        slots = lib.get_slots(token_present=False)
    except Exception as e:  # noqa: BLE001
        raise AgentError(f"Driver không trả về được danh sách khe đọc (slot): {_err_text(e)}", 500)
    tokens, notes = [], []
    for i, slot in enumerate(slots, 1):
        try:
            desc = (slot.slot_description or "").strip() or f"slot {slot.slot_id}"
        except Exception:  # noqa: BLE001
            desc = f"slot {i}"
        try:
            token = slot.get_token()
        except Exception as e:  # noqa: BLE001
            kind = type(e).__name__
            if kind == "TokenNotPresent":
                notes.append(f"   - {desc}: trống (chưa có token)")
            elif kind == "TokenNotRecognised":
                notes.append(f"   - {desc}: có thiết bị nhưng driver KHÔNG nhận ra loại token này")
            else:
                notes.append(f"   - {desc}: lỗi khi đọc token ({_err_text(e)})")
            continue
        tokens.append((slot, token))
        notes.append(f"   - {desc}: có token '{(token.label or '').strip()}'")
    return tokens, notes, len(slots)


def get_lib():
    """Nạp driver. Để 'auto' thì thử lần lượt mọi DLL tìm thấy và chọn DLL đang thấy token."""
    global LIB_PATH
    import pkcs11

    paths = candidate_paths()
    del LAST_PROBE[:]
    if not paths:
        raise AgentError(
            "Không tìm thấy thư viện PKCS#11 nào. "
            "Cài phần mềm của hãng token, rồi điền đường dẫn file .dll vào 'pkcs11_lib' trong config.json.",
            500,
        )
    fallback, problems = None, []
    for path in paths:
        name = Path(path).name
        if not Path(path).exists():
            problems.append(f"Không có file: {path}")
            LAST_PROBE.append(f"{name}: không có file")
            continue
        try:
            lib = pkcs11.lib(path)
        except Exception as e:  # noqa: BLE001
            problems.append(
                f"Không nạp được '{path}': {_err_text(e)}. "
                "Nếu DLL của token là bản 32-bit, hãy dùng agent bản 32-bit (x86)."
            )
            LAST_PROBE.append(f"{name}: không nạp được ({_err_text(e)})")
            continue
        try:
            tokens, notes, count = enumerate_tokens(lib)
            if not tokens:  # có thể token được cắm sau khi agent chạy: khởi tạo lại driver rồi dò lần nữa
                lib.reinitialize()
                tokens, notes, count = enumerate_tokens(lib)
        except Exception as e:  # noqa: BLE001
            LAST_PROBE.append(f"{name}: lỗi khi dò token ({_err_text(e)})")
            fallback = fallback or (path, lib)
            continue
        LAST_PROBE.append(f"{name}: {count} khe đọc, {len(tokens)} token")
        LAST_PROBE.extend(notes)
        if tokens:
            LIB_PATH = path
            return lib
        fallback = fallback or (path, lib)
    if fallback:
        LIB_PATH = fallback[0]
        return fallback[1]
    raise AgentError(" ".join(problems), 500)


def _name(rdn, key):
    value = rdn.native.get(key)
    if isinstance(value, list):
        value = value[0] if value else ""
    return value or ""


def list_certs():
    from asn1crypto import x509
    from pkcs11 import Attribute, ObjectClass

    lib = get_lib()
    tokens, _notes, _count = enumerate_tokens(lib)

    now = datetime.now(timezone.utc)
    certs, errors = [], []
    for slot, token in tokens:
        try:
            with token.open() as session:  # phiên công khai, không cần PIN
                for obj in session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE}):
                    try:
                        cert = x509.Certificate.load(bytes(obj[Attribute.VALUE]))
                    except Exception:  # noqa: BLE001
                        continue
                    if cert.ca:  # bỏ chứng thư CA
                        continue
                    try:
                        cid = bytes(obj[Attribute.ID]).hex()
                    except Exception:  # noqa: BLE001
                        cid = ""
                    try:
                        label = obj[Attribute.LABEL] or ""
                    except Exception:  # noqa: BLE001
                        label = ""
                    not_after = cert["tbs_certificate"]["validity"]["not_after"].native
                    certs.append(
                        {
                            "id": cid,
                            "label": label,
                            "token": (token.label or "").strip(),
                            "slot": slot.slot_id,
                            "cn": _name(cert.subject, "common_name") or cert.subject.human_friendly,
                            "issuer": _name(cert.issuer, "common_name"),
                            "not_after": not_after.isoformat(),
                            "expired": not_after < now,
                        }
                    )
        except Exception as e:  # noqa: BLE001
            # một khe đọc lỗi không được làm hỏng các token khác; chỉ báo lỗi nếu không đọc được token nào
            errors.append(f"'{(token.label or '').strip() or 'không nhãn'}': {_err_text(e)}")
    if not certs and errors:
        raise AgentError("Không mở được token: " + "; ".join(errors), 500)
    return certs


# ---------------------------------------------------------------- ký PDF
def ascii_fold(text):
    text = text.replace("đ", "d").replace("Đ", "D")
    return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()


def make_stamp_style(text):
    """Khung hiển thị chữ ký. Có font TTF thì giữ dấu tiếng Việt, không thì bỏ dấu."""
    from pyhanko.pdf_utils.text import TextBoxStyle
    from pyhanko.stamp import TextStampStyle

    font_path = CONFIG.get("font_path", "")
    if font_path and Path(font_path).exists():
        try:
            from pyhanko.pdf_utils.font.opentype import GlyphAccumulatorFactory

            box_style = TextBoxStyle(font=GlyphAccumulatorFactory(font_path, font_size=9), font_size=9)
            return TextStampStyle(stamp_text=text.replace("%", "%%"), border_width=1, text_box_style=box_style)
        except Exception as e:  # noqa: BLE001
            print(f"[cảnh báo] Không nạp được font, sẽ bỏ dấu tiếng Việt: {e}")
    return TextStampStyle(
        stamp_text=ascii_fold(text).replace("%", "%%"),
        border_width=1,
        text_box_style=TextBoxStyle(font_size=9),
    )


def parse_box(raw):
    try:
        x1, y1, x2, y2 = [float(v) for v in raw.split(",")]
    except Exception:  # noqa: BLE001
        raise AgentError("Vị trí chữ ký không hợp lệ.")
    x1, x2 = sorted((x1, x2))
    y1, y2 = sorted((y1, y2))
    if x2 - x1 < 20 or y2 - y1 < 12:
        raise AgentError("Khung chữ ký quá nhỏ.")
    return (x1, y1, x2, y2)


@app.get("/")
def index():
    return send_from_directory(RES_DIR, "index.html")


@app.get("/api/status")
def api_status():
    return jsonify(ok=True, lib=LIB_PATH, lib_exists=bool(LIB_PATH) and Path(LIB_PATH).exists(), bits=64 if sys.maxsize > 2**32 else 32)


@app.get("/api/certs")
def api_certs():
    return jsonify(certs=list_certs())


@app.post("/api/sign")
def api_sign():
    from pkcs11.exceptions import PinIncorrect, PinLocked
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import fields, signers
    from pyhanko.sign.fields import SigSeedSubFilter
    from pyhanko.sign.pkcs11 import PKCS11Signer

    upload = request.files.get("pdf")
    pin = request.form.get("pin", "")
    cert_id = request.form.get("cert_id", "")
    cert_label = request.form.get("cert_label", "")
    if not upload or not pin:
        raise AgentError("Thiếu file PDF hoặc mã PIN.")
    try:
        page_no = int(request.form.get("page", "1")) - 1
    except ValueError:
        raise AgentError("Số trang không hợp lệ.")
    box = parse_box(request.form.get("box", ""))
    reason = request.form.get("reason", "").strip()
    location = request.form.get("location", "").strip()

    cert = next(
        (c for c in list_certs() if c["id"] == cert_id and c["label"] == cert_label),
        None,
    )
    if cert is None:
        raise AgentError("Không thấy chứng thư đã chọn trên token. Cắm lại token rồi bấm Làm mới.", 404)
    if cert["expired"]:
        raise AgentError("Chứng thư số đã hết hạn.")

    now = datetime.now()
    lines = [f"Ký bởi: {cert['cn']}", f"Ngày ký: {now:%d/%m/%Y %H:%M:%S}"]
    if reason:
        lines.append(f"Lý do: {reason}")
    if location:
        lines.append(f"Nơi ký: {location}")

    try:
        # Mở phiên đúng trên token đã chọn (không dùng open_pkcs11_session vì tham số của nó đổi giữa các bản pyHanko)
        tokens, _notes, _count = enumerate_tokens(get_lib())
        token = next((t for s, t in tokens if s.slot_id == cert["slot"]), None)
        if token is None:
            raise AgentError("Token vừa bị rút ra. Cắm lại token rồi bấm Làm mới.", 404)
        session = token.open(user_pin=pin)
    except AgentError:
        raise
    except PinIncorrect:
        raise AgentError("Sai PIN. Nhập sai nhiều lần liên tiếp token sẽ bị khóa, hãy kiểm tra kỹ.", 401)
    except PinLocked:
        raise AgentError("Token đã bị khóa do nhập sai PIN. Liên hệ nhà cung cấp để mở khóa.", 423)
    except Exception as e:  # noqa: BLE001
        raise AgentError(f"Không mở được phiên làm việc với token: {e}", 500)

    try:
        key_args = {"cert_id": bytes.fromhex(cert_id), "key_id": bytes.fromhex(cert_id)} if cert_id else {"cert_label": cert_label}
        signer = PKCS11Signer(session, use_raw_mechanism=bool(CONFIG.get("use_raw_mechanism", False)), **key_args)

        timestamper = None
        if CONFIG.get("timestamp_url"):
            from pyhanko.sign.timestamps import HTTPTimeStamper

            timestamper = HTTPTimeStamper(CONFIG["timestamp_url"])

        field_name = f"Signature_{int(time.time())}"
        writer = IncrementalPdfFileWriter(io.BytesIO(upload.read()))
        fields.append_signature_field(
            writer, fields.SigFieldSpec(sig_field_name=field_name, on_page=page_no, box=box)
        )
        meta = signers.PdfSignatureMetadata(
            field_name=field_name,
            reason=reason or None,
            location=location or None,
            md_algorithm="sha256",
            subfilter=SigSeedSubFilter.PADES,
        )
        pdf_signer = signers.PdfSigner(
            meta,
            signer=signer,
            stamp_style=make_stamp_style("\n".join(lines)),
            timestamper=timestamper,
        )
        out = pdf_signer.sign_pdf(writer)
        data = out.getvalue() if hasattr(out, "getvalue") else out.read()
    except AgentError:
        raise
    except (ValueError, IndexError, KeyError) as e:
        raise AgentError(f"Không ký được file này (trang không tồn tại hoặc PDF không hợp lệ): {e}")
    except Exception as e:  # noqa: BLE001
        raise AgentError(f"Ký thất bại: {e}", 500)
    finally:
        try:
            session.close()
        except Exception:  # noqa: BLE001
            pass

    return send_file(io.BytesIO(data), mimetype="application/pdf", download_name="signed.pdf")


def dll_bits(path):
    """Đọc header PE để biết DLL là 32 hay 64-bit."""
    import struct

    try:
        with open(path, "rb") as f:
            head = f.read(4096)
        pe = struct.unpack_from("<I", head, 0x3C)[0]
        machine = struct.unpack_from("<H", head, pe + 4)[0]
        return {0x14C: 32, 0x8664: 64}.get(machine)
    except Exception:  # noqa: BLE001 - không đọc được header thì coi như không xác định
        return None


@app.get("/api/diagnose")
def api_diagnose():
    steps = []

    def run(name, fn):
        try:
            steps.append({"name": name, "ok": True, "detail": str(fn() or "")})
            return True
        except Exception as e:  # noqa: BLE001
            steps.append({"name": name, "ok": False, "detail": str(e) if isinstance(e, AgentError) else f"{type(e).__name__}: {e}"})
            return False

    py_bits = 64 if sys.maxsize > 2**32 else 32

    def libs():
        missing = []
        for mod in ("pkcs11", "pyhanko", "asn1crypto"):
            try:
                __import__(mod)
            except Exception as e:  # noqa: BLE001
                missing.append(f"{mod} ({type(e).__name__})")
        if missing:
            raise AgentError("Thiếu thư viện: " + ", ".join(missing) + ". Chạy: pip install -r requirements.txt")
        return "đủ"

    def dll_file():
        paths = candidate_paths()
        if not paths:
            raise AgentError(
                "Chưa tìm thấy DLL của token trong thư mục hệ thống. Cài phần mềm của hãng token, "
                "rồi điền đường dẫn file .dll vào 'pkcs11_lib' trong config.json."
            )
        missing = [p for p in paths if not Path(p).exists()]
        if missing:
            raise AgentError("Không có file: " + ", ".join(missing))
        return "\n".join(paths)

    def bitness():
        lines, sizes = [], set()
        for path in candidate_paths():
            b = dll_bits(path)
            sizes.add(b)
            lines.append(f"{Path(path).name}: {b or '?'}-bit")
        if sizes and py_bits not in sizes and None not in sizes:
            need = sorted(sizes)[0]
            raise AgentError(
                f"Agent đang chạy bản {py_bits}-bit nhưng DLL là bản {need}-bit ({'; '.join(lines)}). "
                f"Hãy dùng agent {need}-bit ({'x86' if need == 32 else 'x64'})."
            )
        return f"agent {py_bits}-bit. " + "; ".join(lines)

    def load():
        get_lib()
        return f"nạp được, đang dùng: {LIB_PATH}"

    def tokens():
        lib = get_lib()
        found, _notes, _count = enumerate_tokens(lib)
        report = "\n".join(LAST_PROBE)
        if not found:
            raise AgentError(
                "Không thấy token nào. Kết quả dò từng DLL:\n" + report + "\n"
                "Cách xử lý: cắm token trước, chờ đèn sáng; thử cổng USB khác; đóng phần mềm khác đang dùng token; "
                "mở phần mềm của hãng token để chắc chắn nó nhận token; rồi bấm Làm mới. "
                "Nếu DLL báo 0 khe đọc, DLL này có thể không phải driver của token đang cắm."
            )
        labels = ", ".join((t.label or "").strip() or "(không nhãn)" for _s, t in found)
        return "thấy: " + labels

    def certs():
        found = list_certs()
        if not found:
            raise AgentError("Token không chứa chứng thư số nào đọc được.")
        return f"{len(found)} chứng thư"

    for name, fn in [
        ("Thư viện Python", libs),
        ("File DLL của token", dll_file),
        ("Loại 32/64-bit", bitness),
        ("Nạp DLL", load),
        ("Nhận token", tokens),
        ("Đọc chứng thư", certs),
    ]:
        if not run(name, fn):
            break
    return jsonify(steps=steps, python_bits=py_bits, config=str(APP_DIR / "config.json"))


def main():
    url = f"http://127.0.0.1:{PORT}/"
    print("=" * 56)
    print(" Agent ký số PDF đang chạy — giữ cửa sổ này mở khi ký.")
    print(f" Giao diện: {url}")
    print(f" PKCS#11:   {LIB_PATH or '(chưa tìm thấy, sửa config.json)'}")
    print(f" Config:    {APP_DIR / 'config.json'}")
    print("=" * 56)
    if CONFIG.get("open_browser", True) and "--no-browser" not in sys.argv:
        target = CONFIG.get("open_url") or url
        threading.Timer(1.0, lambda: webbrowser.open(target)).start()
    app.run(host="127.0.0.1", port=PORT, debug=False)


def already_running():
    """Cổng đang bận: kiểm tra có phải chính agent này đã chạy sẵn không."""
    import urllib.request

    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/api/status", timeout=2) as r:
            return r.status == 200
    except Exception:  # noqa: BLE001
        return False


if __name__ == "__main__":
    try:
        main()
    except OSError as e:
        if already_running():
            print("Agent da chay san. Dang mo trang ky so...")
            if "--no-browser" not in sys.argv:
                webbrowser.open(CONFIG.get("open_url") or f"http://127.0.0.1:{PORT}/")
            time.sleep(2)
        else:
            print(f"\nKhông mở được cổng {PORT}: {e}\nCó thể một phần mềm khác đang dùng cổng này. Đổi 'port' trong config.json.")
            if FROZEN:
                input("Nhấn Enter để đóng...")
    except Exception as e:  # noqa: BLE001
        print(f"\nLỗi: {e}")
        if FROZEN:
            input("Nhấn Enter để đóng...")
