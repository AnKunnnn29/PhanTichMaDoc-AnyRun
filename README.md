# 🛡️ IR Workspace — AI Agent hỗ trợ phân tích mã độc và phản ứng sự cố

Tiểu luận chuyên ngành An toàn thông tin, HCMUTE, HK1 2026–2027 · Nguyễn Thành An, Vũ Văn Thông · GVHD: ThS. Đinh Công Đoan.

Hệ thống nhận báo cáo phân tích hành vi từ **Any.Run**, phân tích sâu từng chỉ báo (IP, domain, URL, hash, tiến trình, registry),
rút ra **tác động cụ thể** (tệp bị mã hóa, dữ liệu bị đánh cắp, cơ chế tự khởi động, phòng thủ bị vô hiệu hóa),
rồi sinh **biện pháp khắc phục riêng cho từng ca** theo NIST SP 800-61, kèm bằng chứng truy ngược được về báo cáo gốc.
Hai **AI Agent** (DeepSeek, Gemini, OpenAI hoặc Ollama) diễn giải chỉ báo và điều tra hồ sơ bằng các công cụ chỉ đọc;
mọi khuyến nghị cần chuyên viên duyệt và **không có lệnh nào được tự thực thi**.

🌐 Bản web: https://ir-workspace.vercel.app

---

## Hệ thống làm gì

```text
Báo cáo Any.Run (Task ID / link công khai / Results.md / JSON / API key)
   │
   ▼ anyrun_public_report.py, analyzer.py, validation.py
Chuẩn hóa dữ liệu: kết nối (PID, port, ASN, quốc gia, uy tín), DNS, HTTP, tiến trình, tệp,
registry, cảnh báo Suricata, chữ ký hành vi, cấu hình mã độc trích xuất
   │
   ▼ evidence.py
Evidence bundle: mỗi dữ kiện có ID ổn định, JSON Pointer và SHA256 của nguồn
   │
   ├──▶ network_intel.py   Hồ sơ từng IP/domain/URL + vai trò (C2 trong cấu hình, C2 theo ThreatFox,
   │                       phát tán, quét SMB, tải payload, kill-switch, hạ tầng hợp lệ, mạng nội bộ…)
   ├──▶ impact_analysis.py Tác động: mã hóa dữ liệu, ngăn khôi phục, đánh cắp thông tin, tự khởi động,
   │                       vô hiệu hóa phòng thủ, lệnh PowerShell đã giải mã, tệp thả ra, C2, lây lan
   ├──▶ remediation.py     Biện pháp riêng cho ca: đối tượng cụ thể + truy vấn xác minh trước + lệnh tham khảo
   │
   ├──▶ analysis_agent.py  AI Agent diễn giải từng IOC (song song theo nhóm)
   └──▶ case_agent.py      AI Agent điều tra hồ sơ: tự chọn công cụ, dựng chuỗi hành vi ATT&CK,
                           đánh giá ảnh hưởng, quyết định cho từng khuyến nghị
   │
   ▼ case_store.py
Chuyên viên duyệt / từ chối / yêu cầu bổ sung từng khuyến nghị (SQLite, có revision)
   │
   ▼ reporter.py, siem_exporter.py
Xuất PDF / HTML / Markdown / JSON và quy tắc SIEM (Splunk, Elastic, Sentinel, Sigma, Suricata, STIX, CSV)
```

### Ví dụ trên báo cáo Any.Run thật

| | WannaCry (task `4a4f9f51-…`) | RedLine Stealer (task `4d6f6b46-…`) |
|---|---|---|
| Đích mạng | 70 đích đều là hạ tầng Microsoft/CDN hợp lệ → **không chặn IP nào** | `185.173.38.57:80` là **C2 trong cấu hình RedLine** → chặn đúng 1 IP |
| Tác động | 61 tệp bị mã hóa (`.WNCRY`, `.HXAMTHY`), 9 ghi chú tiền chuộc, 5 scheduled task ONLOGON quyền cao nhất, Defender bị loại trừ toàn bộ hồ sơ người dùng | Chụp màn hình, cấu hình botnet `200k`, liên lạc C2 |
| Biện pháp | `schtasks /Delete` đúng từng task, `Remove-MpPreference` đúng từng đường dẫn, cô lập máy và khôi phục từ backup ngoại tuyến | Chặn C2 sau khi xác minh, thu hồi phiên và đổi mật khẩu từ máy sạch |
| AI (DeepSeek) | Chuỗi 5 giai đoạn ATT&CK, đồng ý không chặn mạng | Tự thêm discovery T1082 và collection T1113; hoãn reimage tới khi xác minh máy thật |

---

## Chạy nhanh (Windows)

```powershell
python start.py
```

Cần Python 3.10+, lần đầu cần Internet. `start.py` tự chuẩn bị môi trường Python, Ghidra và JDK trong thư mục dự án,
rồi mở `http://127.0.0.1:5000`. Xem [cấu trúc runtime và cách chép offline](tools/README.md).

Hoặc cài thủ công:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-dev.txt
copy .env.example .env      # rồi điền key cần dùng
.\.venv\Scripts\python.exe app.py
```

`Mo-IR-Workspace.cmd` khởi động cả Ollama trên máy và web (xem [docs/LOCAL_CHAT.md](docs/LOCAL_CHAT.md)).
CLI: `python -X utf8 main.py --demo` hoặc `python -X utf8 main.py --report-json Results.md`.

## Cấu hình `.env`

| Biến | Ý nghĩa |
|---|---|
| `AGENT_PROVIDER` | `rules` (mặc định, không gọi AI), `deepseek`, `gemini`, `openai`, `ollama` |
| `AI_PROVIDER` | Nhà cung cấp cho khung chat: `deepseek`, `ollama`, `openai`, `local`, `auto` |
| `DEEPSEEK_API_KEY`, `DEEPSEEK_MODEL` | Key DeepSeek; model mặc định `deepseek-flash` |
| `AISTUDIO_API_KEY` (hoặc `GEMINI_API_KEY`), `GEMINI_MODEL` | Gemini qua endpoint tương thích OpenAI; mặc định `gemini-3.5-flash` |
| `OPENAI_API_KEY`, `OPENAI_API_BASE`, `OPENAI_MODEL` | OpenAI hoặc dịch vụ tương thích OpenAI |
| `OLLAMA_BASE_URL`, `OLLAMA_MODEL` | Model chạy trên máy (model 3B không đủ cho agent nhiều bước) |
| `AGENT_PARALLEL` | Số nhóm IOC gọi AI song song, mặc định 8 |
| `AGENT_RATE_LIMIT_RETRIES` | Số lần chờ rồi thử lại khi gặp HTTP 429, mặc định 4 |
| `MALWAREBAZAAR_AUTH_KEY` (hoặc `ABUSECH_AUTH_KEY`) | Key abuse.ch: tra MalwareBazaar trong chat, ThreatFox/URLhaus cho đích mạng |
| `NETWORK_INTEL_LOOKUPS` | `0` để tắt tra cứu ThreatFox/URLhaus |
| `ANYRUN_API_KEY` | Tùy chọn; chỉ ở máy chủ, không gửi xuống trình duyệt. Để trống ô nhập thì backend dùng key này |
| `GHIDRA_HOME`, `GHIDRA_HEADLESS` | Chỉ cần khi dùng Ghidra cài ngoài dự án |

Không đưa `.env` lên Git. Trên Vercel, đặt các biến này trong **Settings → Environment Variables → Production** rồi Redeploy.

## Nhập dữ liệu

- **Task ID hoặc link task công khai** (`app.any.run/tasks/<uuid>`): không cần API key. Ứng dụng đọc metadata công khai,
  xác minh Task ID và quyền chia sẻ, rồi tải báo cáo HTML có cấu trúc của đúng task. Đây là giao diện công khai có thể thay đổi.
- **Results.md / JSON** xuất từ Any.Run: luôn dùng được, kể cả tài khoản Free/Community.
- **API key Any.Run**: lấy báo cáo qua API chính thức, gửi URL/tệp mới tới sandbox.
- **Dữ liệu mẫu** Emotet / WannaCry / RedLine: **mô phỏng**, chỉ để trải nghiệm; không gửi đi tra threat intel.

## AI Agent

| | Agent diễn giải IOC (`analysis_agent.py`) | Agent điều tra hồ sơ (`case_agent.py`) |
|---|---|---|
| Đầu vào | Nhóm 8 IOC kèm hồ sơ mạng | Tóm tắt hồ sơ; agent tự gọi công cụ để đọc thêm |
| Công cụ | `get_evidence`, `submit_findings` | `list_observables`, `get_evidence`, `search_evidence`, `get_process_tree`, `get_network_profiles`, `get_impact_analysis`, `get_process_story`, `get_static_profile`, `get_family_expectations`, `get_mitre_candidates`, `lookup_mitre`, `get_family_intel`, `lookup_hash`, `list_actions`, `submit_assessment` |
| Đầu ra | Vai trò, mức nguy cơ, ảnh hưởng, cần xác minh cho từng IOC | Chuỗi hành vi theo tactic ATT&CK, đánh giá ảnh hưởng, quyết định cho từng khuyến nghị, câu hỏi cần xác minh |
| Giới hạn | 6 lượt mỗi nhóm, 120 IOC ưu tiên (mạng, tiến trình, registry) | 16 lượt |

**Kiểm soát an toàn**
- Chỉ công cụ chỉ đọc; công cụ ngoài danh sách cho phép không bao giờ chạy và được ghi lại.
- Mọi nhận định phải dẫn evidence **đã đọc**; ID evidence, khuyến nghị hay IOC bịa ra đều bị từ chối.
- Kỹ thuật ATT&CK phải còn hiệu lực trong danh mục v19.2 và đúng tactic; ID đã bị thu hồi được gợi ý ID thay thế (ví dụ T1562.001 → T1685).
- Không đề xuất chặn domain kill-switch WannaCry hay hạ tầng hợp lệ.
- Chuỗi trong báo cáo là dữ liệu không đáng tin; evidence giống chỉ dẫn cho AI được gắn cờ *possible prompt injection*.
- Kết quả không hợp lệ được trả lại cho model sửa; hết lượt thì dùng chế độ quy tắc và ghi nhãn `fallback`.
  Nhóm IOC lỗi chỉ ảnh hưởng nhóm đó (chế độ `partial`).

Trường `mode` trong kết quả cho biết `llm`, `partial`, `fallback` hay `rule_based`. Chỉ dùng kết quả `llm` khi đánh giá chất lượng AI.

## Cấu trúc mã nguồn

| Module | Vai trò |
|---|---|
| `app.py` | Flask web và REST API |
| `main.py`, `start.py` | CLI; khởi động kèm runtime Ghidra/JDK |
| `anyrun_client.py`, `anyrun_public_client.py`, `anyrun_public_report.py` | Lấy báo cáo Any.Run (API, task công khai) và chuẩn hóa |
| `markdown_importer.py`, `validation.py`, `analyzer.py` | Nhập Results.md/JSON, kiểm tra cấu trúc, mô hình dữ liệu |
| `evidence.py` | Evidence bundle truy ngược nguồn; `PIPELINE_VERSION` |
| `network_intel.py` | Hồ sơ và vai trò từng đích mạng; tra ThreatFox/URLhaus |
| `impact_analysis.py` | Tác động cụ thể kèm evidence |
| `remediation.py` | Biện pháp khắc phục riêng cho ca |
| `incident_response.py`, `operational_guidance.py`, `response_policy.py` | Playbook mẫu NIST, hướng dẫn chung, ngoại lệ ứng cứu |
| `analysis_agent.py`, `case_agent.py` | Hai AI Agent |
| `analysis_pipeline.py` | Ghép toàn bộ pipeline, cache theo nội dung và cấu hình |
| `mitre_mapping.py` | Danh mục ATT&CK 19.2, ánh xạ có evidence |
| `ai_assistant.py`, `hash_lookup.py` | Chat hỗ trợ; tra MalwareBazaar |
| `case_store.py`, `history_store.py`, `runtime_storage.py` | Quyết định duyệt (SQLite), lịch sử, lưu trữ theo trình duyệt trên Vercel |
| `reporter.py`, `siem_exporter.py` | Xuất báo cáo và quy tắc SIEM |
| `ghidra_analyzer.py` | Phân tích tĩnh bằng Ghidra headless + static triage |
| `evaluation.py` | Đo trích xuất IOC (P/R/F1) theo manifest nhãn |

## REST API chính

| Endpoint | Chức năng |
|---|---|
| `POST /api/analyze` | Phân tích theo Task ID/link (API key hoặc báo cáo công khai) |
| `POST /api/analyze/json` | Nhập Results.md / JSON |
| `GET /api/demo/<emotet\|wannacry\|redline>` | Dữ liệu mẫu mô phỏng |
| `GET /api/cases/<id>`, `POST /api/cases/<id>/review` | Xem hồ sơ; duyệt/từ chối/yêu cầu bổ sung khuyến nghị |
| `POST /api/export`, `GET /api/exports/<file>` | Xuất PDF/HTML/Markdown/JSON/SIEM |
| `POST /api/ai/remediation(/stream)` | Chat hỗ trợ (kèm tra mã băm) |
| `GET /api/ai/status`, `GET /api/config` | Trạng thái AI; cấu hình công khai (không chứa key) |
| `POST /api/submit/url`, `POST /api/submit/file` | Gửi mẫu tới Any.Run (cần API key) |
| `GET /api/ghidra/status`, `POST /api/ghidra/analyze` | Phân tích tĩnh (chỉ bản chạy trên máy) |
| `GET /api/history/local`, `POST /api/history` | Lịch sử hồ sơ; lịch sử task Any.Run |

## Kiểm thử

```powershell
.\.venv\Scripts\python.exe -m pytest          # Kiểm thử và đo độ phủ
.\.venv\Scripts\python.exe evaluation.py --demo
```

Test không gọi mạng thật (tra cứu threat intel bị tắt, model được giả lập). CI chạy trên GitHub Actions.

## Triển khai Vercel

Mỗi lần push lên `main`, Vercel tự deploy. `.vercelignore` loại `pyproject.toml` (chỉ chứa cấu hình lint) để Vercel cài thư viện từ
`requirements.txt`. Bản web lưu hồ sơ tạm theo trình duyệt, không có Ghidra hay Ollama, và giới hạn mỗi request 60 giây.
Chi tiết: [docs/VERCEL_DEPLOYMENT.md](docs/VERCEL_DEPLOYMENT.md).

## Giới hạn

- Dữ liệu là quan sát trong sandbox với tệp mồi: không chứng minh máy thật trong tổ chức đã nhiễm. Mọi biện pháp đều có bước xác minh trước.
- Vai trò đích mạng và tác động được suy ra bằng quy tắc từ dữ liệu Any.Run; AI chỉ diễn giải thêm, không thay đổi verdict của sandbox.
- Báo cáo công khai có graphSvg được đối chiếu theo UUID tiến trình để dựng quan hệ cha–con. Khi chỉ có tên cha duy nhất, quan hệ vẫn được gắn nhãn suy luận; PID trùng không dùng để gán artifact.
- Kết quả AI phụ thuộc model và có thể khác nhau giữa các lần chạy; cần ghi rõ nhà cung cấp, model và ngày chạy khi báo cáo số liệu.
- Lệnh trong khuyến nghị là mẫu tham khảo, cần chỉnh theo môi trường trước khi dùng.

## Tài liệu khác

- [docs/THESIS_IMPLEMENTATION.md](docs/THESIS_IMPLEMENTATION.md): đối chiếu đề cương, hướng dẫn demo và thực nghiệm
- [docs/VERCEL_DEPLOYMENT.md](docs/VERCEL_DEPLOYMENT.md): bản web và phạm vi
- [docs/LOCAL_CHAT.md](docs/LOCAL_CHAT.md): chat AI chạy trên máy với Ollama
- [docs/HASH_LOOKUP.md](docs/HASH_LOOKUP.md): tra cứu mã băm trong chat
- [tools/README.md](tools/README.md): runtime Ghidra/JDK trong dự án

Phân tích sâu A–F, nguồn dữ liệu, mức bằng chứng và giới hạn: [docs/DEEP_ANALYSIS.md](docs/DEEP_ANALYSIS.md).
