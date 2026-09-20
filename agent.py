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
    "SignatureP11.dll",
]


def load_config():
    path = APP_DIR / "config.json"
    if not path.exists():
        path.write_text(json.dumps(DEFAULT_CONFIG, indent=2, ensure_ascii=False), encoding="utf-8")
    return {**DEFAULT_CONFIG, **json.loads(path.read_text(encoding="utf-8"))}


def resolve_lib(value):
    if value and str(value).lower() != "auto":
        return value
    root = os.environ.get("SystemRoot", "C:\\Windows")
    for folder in (Path(root) / "System32", Path(root) / "SysWOW64"):
        for name in LIB_CANDIDATES:
            if (folder / name).exists():
                return str(folder / name)
    return ""


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
_lib = None


def get_lib():
    global _lib
    if _lib is None:
        if not LIB_PATH or not Path(LIB_PATH).exists():
            raise AgentError(
                f"Không tìm thấy thư viện PKCS#11 '{LIB_PATH}'. "
                "Cài phần mềm của hãng token, rồi điền đường dẫn file .dll vào 'pkcs11_lib' trong config.json.",
                500,
            )
        import pkcs11

        try:
            _lib = pkcs11.lib(LIB_PATH)
        except Exception as e:  # noqa: BLE001
            raise AgentError(
                f"Không nạp được thư viện '{LIB_PATH}': {e}. "
                "Nếu DLL của token là bản 32-bit, hãy dùng agent bản 32-bit (x86).",
                500,
            )
    return _lib


def _name(rdn, key):
    value = rdn.native.get(key)
    if isinstance(value, list):
        value = value[0] if value else ""
    return value or ""


def list_certs():
    from asn1crypto import x509
    from pkcs11 import Attribute, ObjectClass

    lib = get_lib()
    try:
        slots = lib.get_slots(token_present=True)
    except Exception as e:  # noqa: BLE001
        raise AgentError(f"Không đọc được danh sách token: {e}", 500)

    now = datetime.now(timezone.utc)
    certs = []
    for slot in slots:
        try:
            token = slot.get_token()
        except Exception:  # noqa: BLE001 - slot không có token
            continue
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
                            "cn": _name(cert.subject, "common_name") or cert.subject.human_friendly,
                            "issuer": _name(cert.issuer, "common_name"),
                            "not_after": not_after.isoformat(),
                            "expired": not_after < now,
                        }
                    )
        except Exception as e:  # noqa: BLE001
            raise AgentError(f"Không mở được token: {e}", 500)
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
    from pyhanko.sign.pkcs11 import PKCS11Signer, open_pkcs11_session

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
        session = open_pkcs11_session(LIB_PATH, token_label=cert["token"], user_pin=pin)
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

    with open(path, "rb") as f:
        head = f.read(4096)
    pe = struct.unpack_from("<I", head, 0x3C)[0]
    machine = struct.unpack_from("<H", head, pe + 4)[0]
    return {0x14C: 32, 0x8664: 64}.get(machine)


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
        if not LIB_PATH:
            raise AgentError(
                "Chưa tìm thấy DLL của token trong thư mục hệ thống. Cài phần mềm của hãng token, "
                "rồi điền đường dẫn file .dll vào 'pkcs11_lib' trong config.json."
            )
        if not Path(LIB_PATH).exists():
            raise AgentError(f"Không có file: {LIB_PATH}")
        return LIB_PATH

    def bitness():
        b = dll_bits(LIB_PATH)
        if b is None:
            return "không xác định"
        if b != py_bits:
            raise AgentError(
                f"DLL là bản {b}-bit nhưng agent đang chạy bản {py_bits}-bit. Hãy dùng agent {b}-bit "
                f"({'x86' if b == 32 else 'x64'})."
            )
        return f"DLL và agent cùng {b}-bit"

    def load():
        get_lib()
        return "nạp được"

    def tokens():
        lib = get_lib()
        found = []
        for slot in lib.get_slots(token_present=True):
            try:
                found.append((slot.get_token().label or "").strip() or "(không nhãn)")
            except Exception:  # noqa: BLE001
                pass
        if not found:
            raise AgentError(
                "Không thấy token nào. Cắm token, thử cổng USB khác, mở lại phần mềm của hãng để chắc chắn token được nhận, "
                "rồi khởi động lại agent."
            )
        return "thấy: " + ", ".join(found)

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
