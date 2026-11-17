# Plan: thêm sandbox thứ hai, đối chiếu đa nguồn và đo độ chính xác

Lập ngày 17/11/2026. Trạng thái: bước 0–2 đã có mã, chờ API key Triage để chạy trên dữ liệu thật; bước 3–5 chưa làm.

## 0. Tiến độ (17/11/2026)

| Bước | Trạng thái |
|---|---|
| 0. Xác nhận Triage | Đã đọc tài liệu chính thức: tìm theo hash `GET /api/v0/search?query=sha256:…`, báo cáo `…/samples/{id}/overview.json` và `…/{id}/behavioralN/report_triage.json`. API trả 401 khi không có key, kể cả với mẫu công khai. Chưa tìm thấy giới hạn tần suất được công bố. |
| 0. Nguồn tìm mẫu | Đã kiểm tra thật: MalwareBazaar trả `vendor_intel` có liên kết Any.Run, Triage, CAPE, VMRay cho cùng một SHA256 (mẫu `c34af1f1…` có báo cáo Triage `260317-xlg6lafz9j`). |
| 1. Nhập báo cáo Triage | `triage_client.py`, `triage_report.py`. Tải `overview.json` lên như một báo cáo cũng chạy được pipeline. Mới kiểm thử bằng fixture dựng theo tài liệu, **chưa chạy với phản hồi thật của Triage**. |
| 2. Đối chiếu | `sandbox_compare.py`, route `POST /api/cases/<id>/compare/triage`, thẻ "Đối chiếu đa nguồn sandbox" trong Bằng chứng nguồn, mục tương ứng trong bản xuất. |
| 3. Bộ mẫu | Có công cụ `python -m ir_workspace.cli.find_samples`: tra MalwareBazaar theo họ, giữ mẫu có báo cáo trên cả Any.Run và Triage, ưu tiên PE native. Lần chạy đầu ra 30 ứng viên (5 mẫu cho mỗi họ WannaCry, Emotet/Heodo, RedLine, AgentTesla, AsyncRAT, LockBit) trong `reports/evaluation/candidates.csv`. **Chưa thu thập báo cáo, chưa gán nhãn, chưa có 10 mẫu lành tính.** |
| 4. Đánh giá | `evaluation.py` nhận thêm nhãn `reference_family`, `expected_impacts`, `expected_techniques`, `expected_block` và nguồn thứ hai (`second_report_file`, `second_dynamic_file`). Kết quả chấm theo từng nguồn và khi gộp, kèm khoảng tin cậy Wilson 95%, bảng đồng thuận theo chiều, xuất `summary.json` và `results.md`. Chưa có số liệu vì chưa có nhãn. |
| 5 | Chưa làm: viết phần thực nghiệm khi có số liệu. |

Ví dụ một ca trong manifest:

```json
{"id": "wannacry-1", "label_reviewer": "Người gán nhãn", "report_file": "anyrun/wannacry-1.json",
 "second_report_file": "triage/wannacry-1.overview.json", "second_dynamic_file": "triage/wannacry-1.behavioral1.json",
 "expected": [{"type": "ip", "value": "203.0.113.5"}],
 "reference_family": ["WannaCry"], "expected_impacts": ["data_encryption", "persistence"],
 "expected_techniques": ["T1486", "T1053.005"], "expected_block": []}
```

`expected` phải liệt kê đủ mọi observable; các nhãn còn lại là tùy chọn và nhãn nào vắng thì không được chấm. `expected_block: []` nghĩa là không đích nào đáng chặn, nên mọi đề xuất chặn là chặn nhầm.

Việc cần làm để chạy thật: tạo tài khoản Researcher tại tria.ge, đặt `TRIAGE_API_KEY` trong `.env`, mở hồ sơ rồi bấm "Lấy từ Triage và đối chiếu". Sau lần chạy thật đầu tiên cần rà lại `triage_report.py` với JSON thật, vì tài liệu mô tả `tasks` theo hai dạng khác nhau và không có ví dụ cho `report_triage.json`.

## 1. Mục tiêu

Trả lời được câu hỏi "chương trình đúng bao nhiêu %" bằng số liệu có mẫu số rõ ràng, dựa trên hai nguồn sandbox độc lập cho cùng một mẫu.

Một con số "% đúng" duy nhất sẽ không bảo vệ được trước hội đồng, vì chương trình làm nhiều việc khác nhau. Plan này đo bốn việc riêng, mỗi việc có tham chiếu riêng:

| Việc chương trình làm | Tham chiếu để chấm | Chỉ số |
|---|---|---|
| Trích IOC từ báo cáo | Nhãn do người gán | Precision, recall, F1 |
| Nhận diện họ mã độc | Tag của MalwareBazaar | Tỉ lệ đúng |
| Rút ra nhóm tác động và kỹ thuật ATT&CK | Nhãn do người gán, đối chiếu sandbox thứ hai | Precision, recall, mức đồng thuận |
| Quyết định chặn / không chặn đích mạng | ThreatFox và cấu hình C2 sandbox trích được | Tỉ lệ chặn nhầm, tỉ lệ bỏ sót |

Hai sandbox đồng ý với nhau không có nghĩa là đúng, và bất đồng không có nghĩa là sai (C2 đã chết, mẫu phát hiện máy ảo, thời gian chạy khác nhau). Vì vậy mức đồng thuận giữa hai sandbox được báo cáo như một chỉ số riêng, không dùng thay cho nhãn của người.

## 2. Chọn sandbox thứ hai

Đề xuất: **Recorded Future Triage (tria.ge)**.

| Sandbox | Truy cập | Dữ liệu trả về | Đánh giá |
|---|---|---|---|
| Triage (tria.ge) | Tài khoản Researcher miễn phí, API có Bearer key, tìm báo cáo công khai theo hash | JSON: chữ ký hành vi, TTP ATT&CK, cấu hình mã độc trích xuất, tiến trình, mạng | Chọn. Cấu trúc gần Any.Run nhất, có trích cấu hình C2 để đối chiếu |
| Hybrid Analysis | API key phải qua quy trình xét duyệt | JSON tóm tắt, có ATT&CK | Dự phòng nếu không lấy được key Triage |
| VirusTotal `behaviour_summary` | Key miễn phí, giới hạn thấp | Gộp nhiều sandbox thành một bản tóm tắt | Nguồn thứ ba tùy chọn. Chưa xác nhận được endpoint này có mở cho key miễn phí |
| CAPE tự dựng | Cần máy ảo riêng | Đầy đủ nhất | Bỏ: quá nặng so với thời gian còn lại |

Cần xác nhận trước khi viết mã (nửa buổi):

1. Đăng ký tài khoản Triage, lấy API key, gọi thử `GET /api/v0/search?query=sha256:<hash>` và `GET /api/v0/samples/<id>/overview.json`.
2. Kiểm tra tên endpoint báo cáo chi tiết theo task (tài liệu chính thức mới xác nhận `overview.json`).
3. Đọc điều khoản sử dụng API cho mục đích nghiên cứu.

## 3. Thiết kế

### 3.1. Nhập báo cáo Triage

- `ir_workspace/integrations/triage_client.py`: tìm theo SHA256, tải JSON, đọc key từ `TRIAGE_API_KEY`. Cùng kiểu với `anyrun_public_client.py`.
- `ir_workspace/integrations/triage_report.py`: chuyển JSON của Triage về đúng cấu trúc mà `analyzer.py` đang đọc, giống cách `anyrun_public_report.py` và `markdown_importer.py` đã làm. Phần còn lại của pipeline không đổi.
- Mỗi dữ kiện trong evidence bundle đã có `source_id`. Thêm tên sandbox vào nguồn để báo cáo truy được dữ kiện đến từ Any.Run hay Triage.
- Cho phép tải JSON Triage lên bằng tay (giống Any.Run), để không phụ thuộc API khi demo.

### 3.2. Đối chiếu hai nguồn

`ir_workspace/analysis/sandbox_compare.py` nhận hai kết quả pipeline của cùng một SHA256 và trả về, cho từng chiều, ba tập: cả hai cùng thấy, chỉ nguồn A, chỉ nguồn B, kèm hệ số Jaccard.

Các chiều đối chiếu:

- Họ mã độc và verdict.
- Đích mạng (IP, domain, URL) sau khi đã loại hạ tầng hợp lệ.
- C2 trong cấu hình trích xuất.
- Hash tệp thả ra.
- Kỹ thuật ATT&CK.
- Nhóm tác động (9 ID của `impact_analysis.py`).
- Nhóm tác động có đoạn assembly tương ứng (từ `code_evidence.py`).

Từ chối so sánh khi hai báo cáo khác SHA256. Mục chỉ một nguồn thấy được ghi là "chưa được nguồn thứ hai xác nhận", không tự loại bỏ.

### 3.3. Hiển thị và xuất báo cáo

- Giao diện: thêm thẻ "Đối chiếu sandbox" trong hồ sơ, mỗi chiều một hàng với ba cột.
- Bản xuất Markdown/HTML/PDF: thêm mục "Đối chiếu đa nguồn" với bảng tương tự.
- JSON: giữ đủ ba tập cho từng chiều để script đánh giá đọc lại.

## 4. Bộ dữ liệu

Quy mô đề xuất: **30 mẫu, 6 họ, 5 mẫu mỗi họ.** Ba họ đã có trong `family_expectations.json` (WannaCry, Emotet, RedLine) và ba họ thêm để phủ loại khác: AgentTesla (stealer), AsyncRAT (RAT), LockBit (ransomware).

Tiêu chí chọn mẫu:

1. SHA256 có báo cáo công khai trên cả Any.Run và Triage.
2. Có tag họ trên MalwareBazaar, dùng làm tham chiếu độc lập cho họ mã độc.
3. Là PE native nếu được, để có thêm bằng chứng assembly. Mẫu .NET vẫn nhận nhưng ghi chú riêng.

Cách tìm: tra MalwareBazaar theo tag họ; bản ghi của MalwareBazaar thường kèm liên kết tới báo cáo Any.Run và Triage của cùng mẫu (cần kiểm tra lại trường này trong phản hồi API).

Thêm **10 mẫu đối chứng lành tính** (phần mềm hợp lệ đã chạy qua sandbox) để đo tỉ lệ báo động nhầm. Không có nhóm này thì không tính được tỉ lệ chặn nhầm một cách đầy đủ.

Gán nhãn: một người gán, người còn lại rà lại độc lập trên 10 mẫu để tính độ đồng thuận giữa hai người (Cohen's kappa). Nhãn ghi vào manifest mà `evaluation.py` đã hỗ trợ (`label_reviewer`, `expected`).

Rủi ro về dữ liệu: báo cáo công khai của Any.Run có khi chỉ có phần tóm tắt, phải lưu trang từ trình duyệt cho từng mẫu. Với 40 mẫu việc này làm tay được, khoảng một buổi.

## 5. Mở rộng `evaluation.py`

Hiện tại script chấm việc trích IOC theo nhãn (precision, recall, F1) và sinh sẵn phiếu chấm tay. Cần thêm:

1. Manifest nhiều nguồn: mỗi ca có `sources: {anyrun: ..., triage: ...}` và `reference_family`.
2. Nhãn cho nhóm tác động và kỹ thuật ATT&CK, không chỉ IOC.
3. Chấm quyết định chặn: đích bị đề xuất chặn nhưng là hạ tầng hợp lệ (chặn nhầm); C2 đã biết nhưng không được đề xuất chặn (bỏ sót).
4. Bảng đồng thuận giữa hai sandbox theo từng chiều ở mục 3.2.
5. Khoảng tin cậy 95% (Wilson) cho mọi tỉ lệ, vì 30–40 mẫu là ít.
6. Xuất `summary.json`, các tệp CSV và một bảng Markdown dán thẳng vào báo cáo.

Bảng kết quả dự kiến trong báo cáo:

| Chỉ số | Any.Run | Triage | Gộp hai nguồn |
|---|---|---|---|
| IOC: precision / recall / F1 | | | |
| Họ mã độc: tỉ lệ đúng | | | |
| Nhóm tác động: precision / recall | | | |
| ATT&CK: precision / recall | | | |
| Chặn nhầm / bỏ sót | | | |
| Đồng thuận hai sandbox (Jaccard) | — | — | |
| Nhóm tác động có bằng chứng assembly | | | |

Cột "Gộp hai nguồn" cho thấy lợi ích của việc tích hợp: nếu recall tăng mà precision không giảm, đó là luận điểm chính của phần thực nghiệm.

## 6. Thứ tự làm và ước lượng

| Bước | Nội dung | Thời gian |
|---|---|---|
| 0 | Xác nhận truy cập Triage (mục 2) | 0,5 ngày |
| 1 | `triage_client.py`, `triage_report.py`, test với 2 báo cáo thật | 2 ngày |
| 2 | `sandbox_compare.py`, thẻ giao diện, mục trong bản xuất | 2 ngày |
| 3 | Thu thập 40 mẫu từ hai nguồn, gán nhãn | 3 ngày |
| 4 | Mở rộng `evaluation.py`, chạy, sinh bảng | 1,5 ngày |
| 5 | Viết phần thực nghiệm vào báo cáo | 1 ngày |

Tổng khoảng 10 ngày làm việc. Bước 3 không phụ thuộc mã, có thể chia cho người thứ hai làm song song với bước 1 và 2.

Nếu bước 0 thất bại (không lấy được key Triage), chuyển sang Hybrid Analysis; chỉ `*_client.py` và `*_report.py` thay đổi, các bước sau giữ nguyên.

## 7. Việc cần bạn quyết định

1. Quy mô: 30 + 10 mẫu như đề xuất, hay ít hơn cho kịp hạn nộp.
2. Ba họ thêm: AgentTesla, AsyncRAT, LockBit, hay họ khác thầy hướng dẫn muốn.
3. Có dùng VirusTotal làm nguồn thứ ba không.
4. Ai gán nhãn và ai rà lại.
