# Đối chiếu triển khai với đề cương và cách lấy số liệu

Cập nhật ngày 29/10/2026. Đối chiếu với đề cương `DC-10-Nguyen_Thanh_An--Vu_Van_Thong.docx`.
Đây là prototype hỗ trợ chuyên viên phân tích báo cáo sandbox, chưa phải hệ thống ứng cứu production.

## Những khoảng trống đã xử lý

| Yêu cầu trong đề cương | Triển khai | Cách nghiệm thu |
|---|---|---|
| Nhập Task UUID, public report, JSON/Markdown | `app.py`, `main.py`, các adapter hiện có; kiểm tra schema trong `validation.py` | JSON hỏng/rỗng trả lỗi; bản có content nhưng thiếu verdict giữ Unknown |
| Chuẩn hóa IOC, chống trùng | `evidence.py` | Chuẩn hóa IP/domain/hash, giữ nguyên đường dẫn và ngữ cảnh gốc; giá trị sai định dạng không vào blocklist |
| Evidence truy ngược nguồn | `evidence.py` | ID ổn định, SHA256 của JSON chuẩn hóa, JSON Pointer, nội dung nguồn; văn bản nhập có thêm dòng nguồn |
| Agent diễn giải từng IOC | `analysis_agent.py` | Vai trò, diễn giải, ảnh hưởng, cần xác minh, evidence; rules mặc định hoặc LLM cấu hình rõ ràng |
| Giới hạn Agent | `analysis_agent.py` | Chỉ hai công cụ đọc evidence/gửi findings; tối đa 4 bước/batch, 8 IOC/batch, 120 IOC/lượt LLM; lỗi trả fallback có nhãn |
| Hành vi và MITRE | `analysis_pipeline.py`, `mitre_mapping.py` | Chỉ nối process/artifact khi có PID; phân biệt reported/hypothesis; danh mục ATT&CK 19.2 cố định |
| Playbook và chuyên viên duyệt | `incident_response.py`, `case_store.py`, giao diện Quy trình IR | Pending ban đầu; reviewer/lý do; SQLite lưu sự kiện, revision ngăn ghi đè quyết định cũ; không thực thi lệnh |
| Báo cáo có evidence | `reporter.py`, `app.py` | JSON/Markdown đầy đủ, HTML/PDF có phụ lục evidence/Agent/review; export theo case_id lấy snapshot server |
| Đánh giá chương thực nghiệm | `evaluation.py` | Manifest nhãn độc lập, P/R/F1 trích xuất, thời gian chưa cache, rubric người chấm |

Cache cũ theo malware family đã bỏ: cùng family hoặc cùng hash file phụ không được dùng lại kết quả mẫu khác.
Cache mới tính trên toàn bộ input, phiên bản pipeline, prompt/model/provider/endpoint và hash danh mục MITRE.
Khi đổi logic phân tích cần tăng `PIPELINE_VERSION`. Cache exact không chứng minh LLM tái lập hoàn toàn.

## Chạy và trình diễn

PowerShell, trong thư mục repo, Python 3.10 trở lên:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-dev.txt
$env:AGENT_PROVIDER = 'rules'
.\.venv\Scripts\python.exe app.py
```

Mở `http://127.0.0.1:5000`, chạy demo Emotet/WannaCry/RedLine.
Mở Quy trình IR, tìm `powershell`, mở IOC để xem evidence/JSON Pointer/SHA256.
Chọn khuyến nghị, nhập tên/lý do, thử “Yêu cầu bổ sung”. Tải lại và mở lịch sử quyết định.
Xuất JSON/Markdown để lưu bằng chứng cho báo cáo. Dữ liệu demo là mô phỏng, không phải ba ca nhiễm thật.

Để chạy Agent LLM local khi Ollama và model đã sẵn sàng:

```powershell
$env:AGENT_PROVIDER = 'ollama'
$env:OLLAMA_MODEL = 'llama3.1:8b'
$env:OLLAMA_BASE_URL = 'http://localhost:11434'
.\.venv\Scripts\python.exe app.py
```

Kiểm tra trường `agent_analysis.mode`: `llm` là hoàn tất lượt Agent; `fallback` là LLM thất bại và dùng rules;
`rule_based` là chưa gọi LLM. Không dùng kết quả rules/fallback để khẳng định chất lượng suy luận của LLM.
Provider cloud chỉ chạy khi cấu hình `AGENT_PROVIDER=openai` và API key tương ứng. Nội dung evidence được gửi tới provider đã chọn.

DeepSeek đã được hỗ trợ riêng cho cả Agent và trợ lý hội thoại. Cấu hình trong `.env` ở server:

```dotenv
AGENT_PROVIDER=deepseek
AI_PROVIDER=deepseek
DEEPSEEK_API_KEY=<your-key>
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-flash
AI_FAST_MODE=0
```

API key không đưa vào JavaScript, API status hoặc Git. Endpoint/model/JSON output đối chiếu với
[tài liệu DeepSeek](https://api-docs.deepseek.com/quick_start) và [JSON Output](https://api-docs.deepseek.com/guides/json_mode/).
Prompt v5 chia batch nhỏ để tránh JSON bị cắt; có lượt sửa output trong ngân sách 4 bước.

Ngoại lệ ứng cứu trong `response_policy.py` giữ domain/URL kill-switch WannaCry khỏi lệnh chặn.
Khi chưa có quan hệ xác minh giữa IP và domain kill-switch, IP được giữ làm evidence/hunting,
chưa đưa vào blocklist. Đây là biện pháp thận trọng khi thiếu quan hệ nguồn, không kết luận IP lành tính.
Tham chiếu [Microsoft: WannaCrypt ransomware worm](https://www.microsoft.com/en-us/security/blog/2017/05/12/wannacrypt-ransomware-worm-targets-out-of-date-systems/).

CLI sử dụng cùng pipeline:

```powershell
.\.venv\Scripts\python.exe main.py
.\.venv\Scripts\python.exe evaluation.py --demo
.\.venv\Scripts\python.exe -m pytest
```

## Chuẩn bị chương thực nghiệm

`evaluation.py --demo` ghi `reports/evaluation/summary.json`, một JSON mỗi ca và `manual_review.csv`.
Demo không có nhãn độc lập nên `extraction` là null; không tự tạo ground truth từ parser đang được chấm.
Thời gian là một lượt chưa cache mỗi ca, chưa phải nghiên cứu tăng tốc có ý nghĩa thống kê.

Tạo manifest cho các báo cáo thực đã được phép sử dụng. Đường dẫn file tính từ thư mục manifest:

```json
{
  "cases": [{
    "id": "sample-001",
    "dataset_kind": "real_report_independently_labelled",
    "report_file": "samples/sample-001.json",
    "ioc_file": "samples/sample-001-iocs.json",
    "label_reviewer": "Tên người gán nhãn",
    "expected": [
      {"type": "ip", "value": "192.0.2.1"},
      {"type": "file", "value": "sample.exe"}
    ]
  }]
}
```

Ví dụ trên chỉ minh họa định dạng, không phải ground truth của demo.
`expected` phải bao phủ TẤT CẢ observable hỗ trợ trong ca đó: ip/domain/url/md5/sha1/sha256/file/process/registry/mutex.
Nhãn thiếu sẽ được tính là false positive. Ca âm dùng `expected: []`. MITRE đánh giá riêng bằng rubric, không gộp vào IOC F1.

```powershell
.\.venv\Scripts\python.exe evaluation.py --manifest evaluation_manifest.json --output reports/real_evaluation
```

Quy trình đề xuất: chốt dataset và ground truth trước; chạy rules baseline; chạy cùng dataset với Ollama;
ghi model, prompt version và môi trường; để người chấm độc lập chấm vai trò IOC, chuỗi hành vi, hỗ trợ MITRE và an toàn ứng cứu.
Thang 1–5: 1 sai/không có hỗ trợ, 3 dùng được nhưng cần sửa đáng kể, 5 đúng và đủ bằng chứng; ghi rõ lỗi nhận định không được nguồn hỗ trợ.
Đo thời gian chuyên viên làm thủ công cùng tác vụ và lặp nhiều lượt trước khi kết luận tiết kiệm thời gian.
Không báo cáo “độ chính xác” bằng structural completeness/readiness score hoặc số test pass.

## Phân chia phần còn lại theo timeline

| Giai đoạn | Code đã sẵn sàng | Việc cần làm với dữ liệu/báo cáo |
|---|---|---|
| Tuần 6–7: Agent/pipeline | Shared pipeline, mode rõ ràng, tool trace, kiểm tra output | Chọn model phù hợp máy và chạy Agent LLM thật; lưu cả lần fallback |
| Tuần 8: behavior/MITRE | Quan hệ có PID, ánh xạ catalogue và evidence | Chuyên viên đối chiếu từng mapping trên ca thật; không suy chronology khi thiếu timestamp |
| Tuần 9: human approval | SQLite, revision, reviewer/lý do, giao diện | Chụp tình huống duyệt/từ chối/yêu cầu bổ sung; đây là danh tính tự khai, chưa có đăng nhập/RBAC |
| Tuần 10: export | JSON/Markdown và phụ lục HTML/PDF | Dùng JSON làm hồ sơ nguồn đầy đủ; kiểm tra định dạng để đưa hình vào báo cáo |
| Tuần 11: case study | Ba demo mô phỏng để smoke test | Thay bằng report thật Emotet/WannaCry/RedLine có provenance/được phép dùng; không cần lưu mẫu thực thi |
| Tuần 12: đánh giá | Harness + rubric | Hoàn thiện ground truth, số liệu P/R/F1, đánh giá chuyên viên, thời gian và thảo luận giới hạn |

## Giới hạn cần trình bày trung thực

- SHA256 ở evidence là hash biểu diễn JSON chuẩn hóa, không phải hash byte của file upload ban đầu. Markdown có giữ văn bản nhập gốc.
- Kiểm tra tham chiếu chỉ xác nhận value và vị trí nguồn; không chứng minh câu diễn giải đúng hoặc IOC có ác tính.
- Mappings từ report là reported; rules suy ra từ artifact là hypothesis. Tên technique hợp lệ không chứng minh kỹ thuật đã xảy ra.
- Evidence gắn vào action theo nhóm artifact là tham chiếu ứng viên; analyst vẫn cần xác nhận liên quan và điều kiện hành động.
- Các câu lệnh/query là mẫu để xem xét và chỉnh theo môi trường; chưa kiểm chứng với SIEM/EDR thật. Ứng dụng không thực thi khắc phục.
- NIST Rev.3 được tham chiếu bằng chức năng CSF 2.0; các pha playbook hiện có là cách tổ chức nội bộ, không phải chứng nhận tuân thủ.
- SQLite lưu lịch sử ở local, chưa chống người có quyền sửa DB, chưa xác thực reviewer, chưa phù hợp triển khai đa người dùng công khai.
- ML Random Forest cũ là phần phụ. Model khác phiên bản scikit-learn bị vô hiệu hóa để tránh dùng dự đoán không tương thích; cần dữ liệu/huấn luyện/đánh giá riêng trước khi nêu hiệu quả ML.
- Python tests bao phủ cả mock API/LLM; test pass không đồng nghĩa đã gọi Any.Run có quyền truy cập hoặc model LLM thật thành công.

## Kiểm chứng đã chạy trên máy local

Ngày 29/10/2026, Python 3.12.14: `pytest -q` hoàn tất **245 passed**, coverage **85.35%**
trên danh sách module trong `pytest.ini`, có cả app và các module evidence/Agent mới.
Coverage này không phải toàn bộ repository và không phải độ chính xác phát hiện mã độc.
`node --check static/app.js` và `git diff --check` không báo lỗi cú pháp/whitespace.

CUA đã thao tác trực tiếp trên giao diện local:

- Chạy Emotet, WannaCry và RedLine demo, nhận được dashboard tương ứng.
- Lọc PowerShell, mở evidence và thấy JSON Pointer cùng SHA256 nguồn.
- Gửi thiếu tên/lý do bị chặn ở form; gửi “Yêu cầu bổ sung” trên demo lưu được lịch sử.
- Tải lại trang vẫn còn quyết định; các quyết định kiểm thử được ghi người xem xét là `CUA smoke test`.
- Xuất JSON, Markdown, HTML và PDF thành file; JSON có review revision/history từ server.
- Nhập file JSON `{}` hiển thị lỗi thiếu `data/content`, không tạo báo cáo sạch giả.

`evaluation.py --demo` chạy được cả ba ca, ghi summary và rubric; không sinh chỉ số accuracy khi thiếu nhãn.
Ollama local chưa phản hồi trong lần kiểm tra. Sau khi cấu hình DeepSeek, CUA đã xác nhận Agent hoàn tất
18 chỉ báo WannaCry với `mode=llm`, 3 batch, 6 bước đọc evidence/gửi findings hợp lệ; một lượt khoảng 17,9 giây.
Đây là smoke test với model thật trên dữ liệu mô phỏng, không phải đánh giá độ chính xác trên dataset thực.
Trợ lý hội thoại DeepSeek trả lời qua streaming; kiểm tra lại trường hợp kill-switch sau khi bổ sung ngoại lệ.
Frontend có kiểm thử escape HTML, URL protocol và định dạng câu trả lời bằng Node, không cần package ngoài.
CUA xác nhận tải JSON trực tiếp về Downloads sau khi xuất; route tải chỉ phục vụ tên báo cáo được sinh,
không phục vụ `.env` hoặc cơ sở dữ liệu. Đã kiểm tra API status, mã nguồn và JSON xuất không chứa API key.

## Tài liệu chuẩn tham chiếu

- [NIST SP 800-61 Rev.3](https://csrc.nist.gov/pubs/sp/800/61/r3/final).
- [MITRE ATT&CK STIX data](https://github.com/mitre-attack/attack-stix-data), bản snapshot 19.2;
  `data/attack_catalog.json` giữ URL và SHA256 của nguồn tải. Công cụ tái tạo: `scripts/update_attack_catalog.py`.
  Nội dung ATT&CK thuộc MITRE, xem [Terms of Use](https://attack.mitre.org/resources/terms-of-use/).
