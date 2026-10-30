# Tra cứu mã băm trong chat

Mở **Chat hỗ trợ**, dán SHA256, SHA1 hoặc MD5. Không cần mở hồ sơ trước. Khi đang mở hồ sơ, chọn **Tra cứu mã băm** để tra tệp chính; nếu câu hỏi có hash cụ thể thì hash đó được ưu tiên.

Ứng dụng chỉ gọi `query=get_info` đến API metadata, không tải hay gửi tệp thực thi. Auth-Key lấy từ biến máy chủ `MALWAREBAZAAR_AUTH_KEY` trong `.env` local hoặc Environment Variables của Vercel. Không nhập key vào chat hay giao diện web.

Trên Vercel, kết quả tra cứu được trình bày bằng mẫu tiếng Việt có tên tệp, họ mã độc/nhãn nhận diện, loại tệp, tags, ngày ghi nhận và liên kết bản ghi nguồn. Đây không phải một mô hình AI cloud mới. Ollama vẫn dùng cho các câu hỏi điều tra khác ở bản local. Các kết quả tra cứu không tự thay đổi verdict, evidence hay quyết định trong hồ sơ.

Khi không tìm thấy, dùng nguyên câu đã thống nhất:

> Chưa tìm thấy thông tin về mã băm này trong nguồn tra cứu. Kết quả này chưa đủ để kết luận tệp an toàn hay độc hại.

Lỗi xác thực, giới hạn lượt gọi, timeout và phản hồi sai hash có thông báo riêng, không được báo là không tìm thấy dữ liệu. Chỉ cache kết quả tìm thấy/không tìm thấy trong 5 phút, giới hạn 128 hash mỗi tiến trình, tách theo fingerprint của key. Request lookup chịu hạn mức của endpoint chat hiện có.

Tài liệu API: https://bazaar.abuse.ch/api/#query_hash
