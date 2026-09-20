# Ký hợp đồng PDF bằng USB token

Mở PDF trên trình duyệt, đặt khung chữ ký, ký bằng chữ ký số trên USB token (chuẩn PAdES).

```
Trình duyệt (index.html)  ⇄  Agent trên máy (agent.py / KySoPDF.exe)  ⇄  USB token (PKCS#11)
```

## Các file
- `agent.py`: chương trình đọc token và ký (chạy trên máy có cắm token)
- `index.html`: giao diện, agent tự phục vụ, không mở trực tiếp
- `config.json`: cấu hình (đường dẫn DLL của token, cổng...)
- `requirements.txt`: danh sách thư viện Python
- `build.yml`: quy trình để GitHub tự tạo chương trình `KySoPDF` (đặt vào `.github/workflows/build.yml`)

## Dùng cho kế toán (không cần Python)

**Tạo chương trình một lần (người quản trị làm):**
1. Tạo tài khoản github.com, tạo repository mới (Private).
2. Bấm *Add file → Upload files*, tải lên `agent.py`, `index.html`, `config.json`, `requirements.txt`.
3. Bấm *Add file → Create new file*, ở ô tên gõ `.github/workflows/build.yml`, dán nội dung file `build.yml`, bấm *Commit changes*.
4. Vào tab *Actions* → *Build exe* → *Run workflow*. Chờ vài phút tới khi có dấu tích xanh (bước "Smoke test" xanh nghĩa là file chạy được).
5. Bấm vào lần chạy đó, kéo xuống mục *Artifacts*, tải `KySoPDF-x64` (và `KySoPDF-x86` nếu cần).

Nếu không muốn dùng GitHub: trên một máy Windows có Python, mở cmd trong thư mục chứa các file và chạy 2 lệnh:
```
pip install -r requirements.txt pyinstaller
pyinstaller --noconfirm --onedir --noupx --name KySoPDF --add-data "index.html;." --collect-all pyhanko --collect-all pyhanko_certvalidator --collect-all pkcs11 --hidden-import uharfbuzz --hidden-import fontTools agent.py
```
Kết quả nằm ở thư mục `dist\KySoPDF`.

**Cài cho từng kế toán:**
1. Cài phần mềm/driver của hãng token (bắt buộc).
2. Giải nén thư mục `KySoPDF` vào chỗ cố định (ví dụ `C:\KySoPDF`).
3. Bấm chuột phải `KySoPDF.exe` → *Send to* → *Desktop (create shortcut)*.
4. Bấm biểu tượng để chạy. Trình duyệt tự mở trang ký. Giữ cửa sổ đen mở trong lúc ký.
5. Muốn tự chạy khi mở máy: bấm Win+R, gõ `shell:startup`, chép shortcut vào thư mục đó.

File `config.json` tự được tạo ở lần chạy đầu, không cần chép thêm.
Bản `x64` và `x86`: thử `x64` trước. Nếu báo lỗi 32/64-bit thì dùng `x86` (nhiều token chỉ có DLL 32-bit).
Nếu Windows Defender báo nhầm, kiểm tra file bằng virustotal.com, rồi thêm thư mục `KySoPDF` vào danh sách loại trừ.

## Chạy bằng Python (để thử)
```
pip install -r requirements.txt
python agent.py
```
Rồi mở `http://127.0.0.1:8765` (không mở file `index.html` trực tiếp).

## Cấu hình `config.json`
| Khóa | Ý nghĩa |
|---|---|
| `pkcs11_lib` | `"auto"` để tự dò, hoặc đường dẫn DLL PKCS#11 của token (dùng `\\` trong JSON) |
| `font_path` | Font TTF có tiếng Việt cho khung chữ ký (mặc định Arial) |
| `timestamp_url` | Máy chủ dấu thời gian (TSA), tùy chọn |
| `use_raw_mechanism` | Đặt `true` nếu token báo lỗi mechanism |
| `allowed_origins`, `open_url` | Chỉ dùng khi đặt giao diện trên máy chủ web riêng |
| `port` | Cổng của agent |

Nút **Kiểm tra kết nối token** trên giao diện cho biết lỗi nằm ở bước nào.

## Lưu ý
- Chưa thử với token thật trên Windows trong lúc viết.
- Nhập sai PIN nhiều lần sẽ khóa token.
- Chưa hỗ trợ chữ ký dạng hình ảnh và PDF đặt mật khẩu.
- Tính pháp lý phụ thuộc chứng thư số của CA được cấp phép và thỏa thuận giữa các bên.
