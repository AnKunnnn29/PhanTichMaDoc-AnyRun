# Runtime trong dự án

Chạy tại thư mục repo:

```powershell
python start.py
```

Yêu cầu ban đầu: Windows x64, Python 3.10+ và Internet cho lần chuẩn bị đầu tiên.
Lệnh này chuẩn bị `.venv`, Ghidra và JDK trong dự án rồi chạy web.
Không cần cài Ghidra/Java toàn máy hoặc thiết lập đường dẫn ổ D.

```text
tools/
  runtime-manifest.json             # URL và SHA256 cố định, đưa lên Git
  ghidra/ghidra_12.1.4_PUBLIC/       # Bộ Ghidra thực, tạo ở máy chạy
  java/jdk-21/                      # JDK Temurin thực, tạo ở máy chạy
  .downloads/                      # Cache ZIP đã kiểm checksum
```

Các bộ runtime được giữ nguyên giấy phép/notice từ bản phân phối.
Ghidra được lấy từ release chính thức của NSA; JDK từ Eclipse Adoptium.
Manifest chốt URL/SHA256 để lần clone sau chuẩn bị cùng bản, không lấy tùy ý bản latest.
Runtime và cache được `.gitignore`; Git lưu mã nguồn, manifest và bộ khởi động.
Vì vậy **clone mới cần Internet để tải runtime**, không phải một bản clone có sẵn toàn bộ binary offline.
Nếu sao chép cả thư mục dự án đã chuẩn bị, bao gồm hai thư mục runtime, không cần tải lại Ghidra/JDK.

Chỉ chuẩn bị, chưa mở web:

```powershell
python start.py --setup-only
```

Sau lần đầu, nếu cần mở web mà không kiểm tra package lại:

```powershell
.\.venv\Scripts\python.exe app.py
```

Web lõi vẫn dùng được khi không có Ghidra; phân tích file khi đó chỉ trả triage cơ bản:

```powershell
python start.py --without-ghidra
```

Windows với đường dẫn tiếng Việt có thể làm Java native launcher lỗi mã hóa.
Module tạo một junction tên ASCII trong TEMP trỏ đến dự án để khởi chạy; runtime thực vẫn nằm trong `tools/`.
Không sửa system PATH/JAVA_HOME, registry hoặc cấu hình ổ đĩa. TEMP cần ở đường dẫn ASCII;
nếu máy không hỗ trợ junction local, hãy clone dự án vào thư mục ASCII trên ổ đĩa local.
Linux/macOS chưa có bootstrap tự tải JDK trong bản này; vẫn có thể cấu hình Ghidra/JDK ngoài bằng môi trường.

API key DeepSeek/Any.Run là cấu hình riêng từng máy qua `.env`, không đi kèm repo.
