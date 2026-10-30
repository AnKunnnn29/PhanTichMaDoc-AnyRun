# Chat AI miễn phí trên máy

Mở `Mo-IR-Workspace.cmd` trong thư mục dự án, vào http://127.0.0.1:5000, chọn báo cáo hoặc chạy dữ liệu mẫu, rồi nhấn **Chat hỗ trợ**. Khung chat dùng hồ sơ đang mở và giữ các lượt trao đổi trong phiên đó; chuyển sang hồ sơ khác sẽ xóa ngữ cảnh hội thoại cũ.

Ứng dụng dùng Ollama và mô hình Qwen2.5 3B chạy trên máy, không cần API key, tài khoản Muse hay kết nối Muse.ai. Sau khi đã tải mô hình, nội dung hỏi đáp được xử lý tại máy. Những tính năng lấy báo cáo/gửi mẫu Any.Run vẫn cần mạng riêng theo cách dùng của chúng.

Runtime Ollama nằm trong `tools/ollama`, mô hình trong `tools/ollama-models` ở ổ D. Bộ khởi động chỉ mở dịch vụ AI tại `127.0.0.1:11434` và web tại `127.0.0.1:5000`; không mở dịch vụ ra Internet. Runtime, mô hình, `.env`, hồ sơ và log không được đưa vào Git hay gói deploy Vercel.

Nhãn trong chat phân biệt **AI trên máy** với **Hỗ trợ theo quy tắc** khi mô hình chưa hoạt động hoặc lỗi. Lần hỏi đầu có thể chậm vì cần nạp mô hình. Mô hình nhỏ có thể hiểu sai tiếng Việt hoặc suy luận sai: đối chiếu nguồn và log trước khi dùng đề xuất. Các câu trả lời không tự thực thi biện pháp khắc phục.

## Trên bản Vercel

Giao diện và khung chat vẫn có sẵn, nhưng mô hình trên máy không nằm trên Vercel. Bản online trả lời theo quy tắc khi chưa cấu hình AI cloud hoặc máy chủ mô hình. Việc mở bản online trên cùng máy không tự nối với Ollama local.

## Phần khắc phục mới

Mỗi biện pháp có mục tiêu, đối tượng cần xác minh, các bước thực hiện, tiêu chí kiểm tra và phương án khi có ảnh hưởng. Bằng chứng nguồn có trang riêng. Các lệnh playbook cũ được giữ ở phần tham khảo thu gọn, cần kiểm tra đích và môi trường trước khi dùng. Hồ sơ cũ cần phân tích lại từ báo cáo nguồn để có các trường hướng dẫn mới; dữ liệu mẫu mới luôn có các trường đó.

Tham chiếu: [Ollama trên Windows](https://docs.ollama.com/windows), [Qwen2.5 3B](https://ollama.com/library/qwen2.5:3b), [Ollama Chat API](https://docs.ollama.com/api/chat).
