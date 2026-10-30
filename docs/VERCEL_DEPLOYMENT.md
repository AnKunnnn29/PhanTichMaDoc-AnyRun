# Bản web IR Workspace

Địa chỉ: https://ir-workspace.vercel.app

Giao diện hướng người dùng qua bốn bước: nhập dữ liệu, đọc kết quả và dẫn chứng, xem xét khuyến nghị, xuất báo cáo. Trang Bắt đầu có dữ liệu mô phỏng WannaCry và phần giải thích chức năng. Các thống kê và định dạng xuất SIEM nâng cao được thu gọn, có thể mở khi cần.

## Phạm vi bản Vercel

- Nhập Results.md / JSON, dùng dữ liệu mẫu, xem kết quả, IOC, MITRE, quy trình và xuất báo cáo.
- Có thể dán link task hoặc Task ID công khai mà không cần API key. Ứng dụng dùng client Chrome-compatible để đọc metadata công khai, xác minh Task ID/quyền chia sẻ, lấy SHA256 rồi tải báo cáo HTML có cấu trúc của đúng task. Không dùng cookie tài khoản, tiện ích hay dịch vụ giải CAPTCHA. Task riêng tư, đang chạy hoặc dạng URL không có SHA256 có thể chưa tải được bằng luồng này. Đây là giao diện web công khai có thể thay đổi, cần giữ luồng nhập báo cáo dự phòng.
- Kiểm chứng trên Vercel ngày 30/10/2026: task `4a4f9f51-083f-47e7-9d1d-424bfcdbbeea` trả HTTP 200 sau khoảng 4 giây; dữ liệu khớp task, 39 IP và 9 đề xuất xử lý. Đây là kiểm tra kết nối/luồng, không phải đánh giá độ chính xác phát hiện mã độc.
- API key Any.Run do người dùng cung cấp. Bản triển khai không chứa `.env`, báo cáo cá nhân, mẫu mã độc hay khóa API trên máy.
- Hồ sơ, quyết định duyệt và tệp xuất nằm trong thư mục tạm riêng theo cookie của từng trình duyệt. Đây không phải lưu trữ bền vững: các lần gọi có thể chạy ở máy chủ khác hoặc mất dữ liệu khi máy chủ khởi động lại. Tải báo cáo sau khi xem xét. Không dùng bản này thay kho hồ sơ nghiệp vụ.
- Phân tích mặc định dùng rules, không quảng bá là đã gọi mô hình AI thật. Chạy Ollama và Ghidra bằng bản trên máy tính; cloud AI cần cấu hình provider và khóa ở môi trường máy chủ.
- Gửi URL/tệp tới Any.Run lấy Task ID vẫn có sẵn khi API key có quyền. Chờ sandbox tự động bằng tiến trình nền chỉ dùng ở bản local. Trên web, sau khi sandbox hoàn tất, nhập Task ID để lấy báo cáo.
- Không có đăng nhập người duyệt: tên duyệt là thông tin tự khai của prototype.

## Triển khai lại

`vercel.json` dùng Flask, Python 3.12 và giới hạn mỗi request 60 giây. `.vercelignore` loại dữ liệu cá nhân, mẫu, runtime local và các tệp kiểm thử. Cấu hình môi trường riêng từng project; không đưa `.env` lên hosting.

Bản triển khai được đóng gói từ các module Python, `static/`, `templates/` và `data/` vào thư mục riêng trước khi triển khai bằng Vercel CLI. Mã nguồn được lưu trên nhánh `main` của GitHub. Việc đẩy mã nguồn lên GitHub chưa tự triển khai lên Vercel; thay đổi chỉ xuất hiện trên website sau lần deploy tiếp theo.

Để triển khai sử dụng thực tế lâu dài, cần thay SQLite/JSON/thư mục tạm bằng cơ sở dữ liệu và object storage bền vững, cùng đăng nhập và phân quyền. Ghidra cần worker hoặc máy chủ riêng.
