# 🛡️ AnyRun Malware Incident Response Tool

> Hệ thống phân tích mã độc thực tế từ **Any.Run Sandbox** và tự động sinh **Quy trình Phản ứng Sự cố (Incident Response Playbook)** theo chuẩn **NIST SP 800-61** kết hợp **MITRE ATT&CK Framework**.

---

## 📌 Mục tiêu chương trình

Khi một tổ chức bị nhiễm mã độc, đội ngũ bảo mật cần nhanh chóng:
1. **Hiểu rõ mã độc** đang làm gì (hành vi, IOC, kỹ thuật tấn công)
2. **Có ngay kế hoạch hành động** để ngăn chặn, loại bỏ và phục hồi

Chương trình này giải quyết cả hai bài toán trên tự động: lấy dữ liệu phân tích từ Any.Run → phân tích → sinh ra quy trình IR cụ thể với từng lệnh thực thi.
Chạy app: run main.py
Chạy LLM Ollama: "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe" run llama3.1:8b
---

## 🗂️ Cấu trúc dự án

```
Phan Tich Ma Doc/
├── main.py                  # CLI entry point
├── app.py                   # Web GUI (Flask server)
├── anyrun_client.py         # Kết nối Any.Run API
├── analyzer.py              # Phân tích & chuẩn hóa dữ liệu
├── incident_response.py     # Sinh IR Playbook
├── reporter.py              # Xuất báo cáo terminal + file
├── demo_data.py             # Dữ liệu mẫu Emotet (demo)
├── templates/index.html     # Giao diện web
├── static/style.css         # CSS dark theme
├── static/app.js            # JavaScript frontend
├── requirements.txt
├── .env.example
└── reports/                 # Thư mục báo cáo đầu ra
```

---

## ⚙️ Chi tiết chức năng từng module

### 1. `anyrun_client.py` – Kết nối Any.Run API

Module đóng vai trò **giao tiếp với Any.Run REST API**, xử lý xác thực và các loại request.

| Hàm | Chức năng |
|-----|-----------|
| `AnyRunClient(api_key)` | Khởi tạo client, gắn API key vào header `Authorization` |
| `get_task_report(uuid)` | Lấy báo cáo phân tích đầy đủ của một task theo UUID |
| `get_task_iocs(uuid)` | Lấy danh sách IOC (IP, domain, hash, URL) của task |
| `get_history(limit)` | Lấy lịch sử các task đã phân tích của tài khoản |
| `submit_file(path)` | Upload file mẫu lên Any.Run để sandbox phân tích |
| `submit_url(url)` | Gửi URL nghi ngờ lên Any.Run để sandbox phân tích |
| `wait_for_task(uuid)` | Polling API đến khi task hoàn tất, trả về report |

**Xử lý lỗi:** Phân biệt rõ các loại lỗi: `AnyRunAuthError` (sai API key), `AnyRunNotFoundError` (không tìm thấy task), `AnyRunRateLimitError` (vượt giới hạn tốc độ).

---

### 2. `analyzer.py` – Phân tích & chuẩn hóa dữ liệu

Module **parse JSON thô từ API** thành các data model có cấu trúc rõ ràng để các module khác sử dụng.

**Data models:**

| Model | Thông tin chứa |
|-------|----------------|
| `FileInfo` | Tên file, kích thước, MD5, SHA1, SHA256, loại file |
| `ThreatInfo` | Verdict (Malicious/Suspicious/Clean), threat level 0-4, tên mã độc, tags, MITRE techniques |
| `NetworkActivity` | Danh sách IP, domain, URL C2; HTTP requests; DNS queries |
| `ProcessActivity` | Danh sách tiến trình, tiến trình bị inject, file dropped, registry keys, mutexes |
| `IOCData` | Tổng hợp tất cả IOC: IP, domain, URL, hash, filename |
| `MalwareAnalysisResult` | Kết hợp tất cả model trên + metadata phân tích |

**Hàm chính:** `MalwareAnalyzer.parse_report(report_json, ioc_json)` → `MalwareAnalysisResult`

---

### 3. `incident_response.py` – Sinh IR Playbook

**Trung tâm** của hệ thống. Từ kết quả phân tích, module tự động tạo ra quy trình phản ứng sự cố theo **5 phase của NIST SP 800-61**.

**Quy trình được sinh:**

| Phase NIST | Nội dung hành động |
|-----------|---------------------|
| **Identification** | Xác nhận verdict, ghi lại hash, URL Any.Run |
| **Containment** | Chặn C2 IP/domain tại firewall, kill tiến trình bị inject, vô hiệu hóa persistence |
| **Eradication** | Xóa file dropped, dọn registry, quét Defender, kiểm tra scheduled tasks |
| **Recovery** | Cập nhật Windows, reset credentials, bật lại bảo mật |
| **Lessons Learned** | Viết báo cáo, cập nhật threat intel feed, cải thiện phòng thủ |

**Xử lý MITRE ATT&CK tự động:** Với mỗi technique phát hiện, hệ thống thêm hành động đặc thù:

| MITRE Technique | Hành động thêm |
|-----------------|----------------|
| T1566 – Phishing | Quarantine email, search mailbox Exchange/M365 |
| T1055 – Process Injection | Dump memory với Volatility, procdump |
| T1547 – Boot Persistence | Kiểm tra Autoruns, Run keys, Scheduled Tasks |
| T1082/T1057 – Discovery | Đánh giá phạm vi xâm phạm, kiểm tra DLP logs |
| T1486 – Ransomware | Cô lập khẩn cấp, backup memory, không tắt máy |

**Mỗi `IncidentAction` bao gồm:**
- `priority`: P1-Critical → P4-Low
- `phase`: Phase NIST tương ứng
- `title` + `description`: Mô tả hành động
- `commands`: Lệnh PowerShell/CMD cụ thể để thực thi
- `notes`: Ghi chú quan trọng

---

### 4. `reporter.py` – Xuất báo cáo

Chịu trách nhiệm **trình bày kết quả** theo 2 hình thức:

**Terminal (Rich):**
- `TerminalReporter.print_analysis()`: In bảng thông tin mã độc, MITRE, network đẹp có màu
- `TerminalReporter.print_playbook()`: In từng bước IR theo phase, có syntax highlight cho lệnh

**File:**
- `ReportExporter.export_markdown()`: Báo cáo đầy đủ dạng `.md` (chia sẻ, in ấn)
- `ReportExporter.export_json()`: Dữ liệu `.json` có cấu trúc (import vào SIEM/SOAR)

---

### 5. `app.py` – Web GUI (Flask Server)

Backend phục vụ giao diện web. Expose các REST API endpoint:

| Endpoint | Method | Chức năng |
|----------|--------|-----------|
| `GET /` | GET | Trả về trang web chính |
| `/api/demo` | GET | Phân tích demo Emotet (không cần API key) |
| `/api/analyze` | POST | Phân tích task UUID với API key |
| `/api/submit/url` | POST | Submit URL lên Any.Run |
| `/api/submit/file` | POST | Upload và submit file lên Any.Run |
| `/api/history` | POST | Lấy lịch sử task của tài khoản |
| `/api/export` | POST | Xuất báo cáo Markdown hoặc JSON ra file |

---

### 6. `main.py` – CLI (Command Line Interface)

Giao diện dòng lệnh với 2 chế độ: **interactive menu** và **tham số trực tiếp**.

```bash
python -X utf8 main.py                      # Interactive menu
python -X utf8 main.py --demo               # Demo Emotet
python -X utf8 main.py --task <UUID>        # Phân tích theo UUID
python -X utf8 main.py --file <path>        # Submit file
python -X utf8 main.py --url <url>          # Submit URL
python -X utf8 main.py --history            # Xem lịch sử
python -X utf8 main.py --no-export          # Chỉ in terminal, không lưu file
```

---

### 7. `demo_data.py` – Dữ liệu Demo

Chứa dữ liệu JSON mô phỏng phân tích mã độc **Emotet** thực tế, bao gồm:
- 12 MITRE ATT&CK techniques (T1566, T1055, T1547, T1486…)
- 4 C2 IP addresses + 4 malicious domains
- 3 HTTP C2 requests
- 4 tiến trình (2 bị inject: `rundll32.exe`, `svchost.exe`)
- 3 file dropped (payload DLL, giả svchost, LNK startup)
- 3 registry persistence keys

---

## 🖥️ Giao diện Web GUI

Truy cập tại `http://localhost:5000` sau khi chạy `python app.py`.

### Các trang chính:

| Trang | Chức năng |
|-------|-----------|
| **Tổng quan** | Dashboard hiển thị threat level, MITRE techniques, thông tin file, network activity, process tree |
| **Phân tích** | Form nhập API key, chọn chế độ: Task UUID / Submit URL / Submit File / Demo |
| **IR Playbook** | Hiển thị toàn bộ quy trình IR theo phase, có lệnh thực thi copy-paste, nút export |
| **IOC Blocklist** | Hiển thị tất cả IOC theo loại (IP/domain/hash/URL), có firewall block rules tự sinh |
| **Lịch sử** | Xem danh sách các task đã phân tích trên tài khoản Any.Run |

---

## 🚀 Cài đặt & Chạy

### 1. Cài Python packages

Yêu cầu:

- Python 3.10+.
- Git.
- Ollama nếu muốn dùng AI Agent local.

Windows PowerShell:

```powershell
git clone <repo-url>
cd "Phan Tich Ma Doc"

python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

CMD:

```cmd
python -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 2. Tạo file cấu hình

```bash
cp .env.example .env
```

Trên Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

Sửa `.env`:

```env
ANYRUN_API_KEY=your_anyrun_api_key_here
AI_PROVIDER=ollama
OLLAMA_ENABLED=1
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.1:8b
OLLAMA_TIMEOUT=120
OLLAMA_NUM_PREDICT=500
```

Không commit file `.env` lên GitHub.

### 3. Cài Ollama model cho AI Agent

Cài Ollama từ: https://ollama.com/download

Sau đó pull model:

```powershell
ollama pull llama3.1:8b
```

Nếu Windows chưa nhận lệnh `ollama`, dùng đường dẫn đầy đủ:

```powershell
& "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe" pull llama3.1:8b
```

Máy yếu có thể dùng model nhẹ hơn:

```powershell
ollama pull llama3.2:3b
```

và đổi `.env`:

```env
OLLAMA_MODEL=llama3.2:3b
```

### 4. Train hoặc dùng sẵn model ML

Repo có thể chứa sẵn `models/rf_threat_model.pkl`. Nếu chưa có, train lại:

```bash
python -X utf8 train_ml.py --synthetic 60
```

### 5. Chạy app

```bash
python app.py
```

Mở:

```text
http://localhost:5000
```

Chạy CLI demo:

```bash
python -X utf8 main.py --demo
```

---

## 🔑 Lấy API Key

1. Đăng ký tại [app.any.run](https://app.any.run/)
2. Vào **Profile → API and Limits**
3. Copy API key → dán vào Web GUI hoặc file `.env`

> Gói **Free** có giới hạn số task/tháng. Không cần key để chạy **Demo mode**.

---

## 📤 Output

Mỗi lần phân tích tạo ra 2 file trong `reports/`:

| File | Mô tả |
|------|-------|
| `IR_Report_YYYYMMDD_HHMMSS.md` | Báo cáo Markdown đầy đủ, có thể in |
| `IR_Report_YYYYMMDD_HHMMSS.json` | Dữ liệu JSON, import vào SIEM/SOAR |

---

## 🔄 Luồng hoạt động tổng thể

```
[Any.Run Sandbox]
      │ JSON (report + IOC)
      ▼
[anyrun_client.py]  ──fetch──►  Any.Run REST API
      │
      ▼
[analyzer.py]       ──parse──►  MalwareAnalysisResult
      │
      ▼
[incident_response.py] ──gen──► IncidentResponsePlaybook
      │                          (NIST phases + MITRE mapping)
      ├──► [reporter.py]   ──►  Terminal (Rich) + File (.md/.json)
      └──► [app.py / JS]   ──►  Web Dashboard
```

---

*Dựa trên: NIST SP 800-61 Rev.2 | MITRE ATT&CK v14 | Any.Run Sandbox API v1*

Viewed README.md:39-85

Dưới đây là kịch bản thực tế chi tiết khi đã có API key:

---

## 🎬 Kịch bản: Phát hiện email nghi ngờ chứa file độc hại

### Bối cảnh
> Nhân viên công ty nhận được email có file đính kèm `Invoice_Q4.doc`. SOC nhận alert → cần phân tích ngay.

---

### Bước 1 – Chuẩn bị

```bash
# Chạy web GUI
python app.py
# Mở trình duyệt → http://localhost:5000
```

Hoặc dùng CLI:
```bash
python -X utf8 main.py
```

---

### Bước 2 – Nhập API Key

**Trên Web:**
1. Vào trang **Phân tích** (sidebar trái)
2. Dán API key vào ô **Any.Run API Key**
3. Nhấn **Lưu Key** (key được lưu vào localStorage, không cần nhập lại lần sau)

**Hoặc dùng `.env`:**
```bash
copy .env.example .env
# Mở .env, sửa:
ANYRUN_API_KEY=abc123xyz_your_real_key
```

---

### Bước 3 – Lựa chọn cách phân tích

#### Tình huống A: Đã có Task UUID (ai đó đã chạy trên Any.Run)

**Web:** Tab **Task UUID** → dán UUID → **Phân tích**

```bash
# CLI:
python -X utf8 main.py --task 550e8400-e29b-41d4-a716-446655440000
```

#### Tình huống B: Có file mẫu cần phân tích (phổ biến nhất)

**Web:** Tab **Submit File** → kéo thả `Invoice_Q4.doc` → **▶ Submit & Phân tích ngay**

→ Progress bar hiện lên, chờ 1-3 phút, kết quả tự hiện.

```bash
# CLI:
python -X utf8 main.py --file "C:\Quarantine\Invoice_Q4.doc"
```

#### Tình huống C: Có URL nghi ngờ trong log

**Web:** Tab **Submit URL** → nhập URL → **▶ Submit & Phân tích ngay**

```bash
# CLI:
python -X utf8 main.py --url "http://evil-site.ru/download/payload.exe"
```

#### Tình huống D: Xem lại các task đã phân tích gần đây

**Web:** Trang **Lịch sử** → nhấn **Xem lịch sử** → click **Phân tích** trên task bất kỳ

```bash
# CLI:
python -X utf8 main.py --history
```

---

### Bước 4 – Đọc kết quả trên Dashboard

Sau khi phân tích xong, dashboard hiện:

| Thẻ | Thông tin cần chú ý |
|-----|---------------------|
| **Threat Assessment** | Verdict `Malicious`, Threat Level `2/4`, tên mã độc `Emotet` |
| **Thông tin File** | SHA256 → copy paste kiểm tra VirusTotal |
| **MITRE ATT&CK** | Xem kỹ các technique như T1055 (Injection), T1486 (Ransomware) |
| **Hoạt động mạng** | Tab **IPs** → danh sách C2 cần chặn ngay |
| **Tiến trình** | File nào bị drop, registry key nào bị thêm |

---

### Bước 5 – Thực hiện IR Playbook

Vào trang **IR Playbook**:

1. Đọc **tóm tắt mức độ** và **biện pháp ưu tiên** ở đầu trang
2. Mở từng **Phase** (click để mở/đóng)
3. **Copy lệnh** từ code block → chạy trực tiếp trên máy bị nhiễm

Ví dụ lệnh được sinh tự động:
```powershell
# Phase Containment - Chặn C2:
netsh advfirewall firewall add rule name="Block_185.220.101.45" dir=out action=block remoteip=185.220.101.45

# Phase Eradication - Xóa file độc:
Remove-Item -Force "C:\Users\Admin\AppData\Local\Temp\payload.dll"

# Phase Eradication - Xóa persistence key:
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdater" /f
```

---

### Bước 6 – Lấy IOC để chặn toàn mạng

Vào trang **IOC Blocklist**:

- Nhấn **📋 Copy tất cả** → dán vào firewall/SIEM
- Dùng block **Firewall Rules** được sinh sẵn để chặn hàng loạt
- Nhấn **⬇ Export JSON** → import vào SIEM (Splunk, ELK, Wazuh...)

---

### Bước 7 – Xuất báo cáo

Trên trang **IR Playbook**:
- **⬇ Markdown** → gửi email cho quản lý / lưu hồ sơ
- **⬇ JSON** → import vào hệ thống SOAR
- **📁 Mở Folder** → mở thư mục `reports/` xem file vừa xuất

```bash
# CLI - xuất cả 2 định dạng tự động:
python -X utf8 main.py --task <UUID>
# → Tạo reports/IR_Report_20260507_135400.md
# → Tạo reports/IR_Report_20260507_135400.json
```

---

### Sơ đồ tóm tắt kịch bản

```
Phát hiện file nghi ngờ
        │
        ▼
  Chọn phương thức
  ┌─────┬──────┬─────┐
  │UUID │ File │ URL │
  └──┬──┴──┬───┴──┬──┘
     │     │      │
     └──────▼──────┘
    Any.Run Sandbox
    (1-3 phút phân tích)
        │
        ▼
   Dashboard kết quả
   ├─ Threat level
   ├─ MITRE ATT&CK
   └─ C2 IP/Domain
        │
        ▼
   IR Playbook
   ├─ Containment → Chặn C2
   ├─ Eradication → Xóa malware
   └─ Recovery → Hardening
        │
        ▼
   Export báo cáo (.md / .json)
   → Gửi quản lý / nạp SIEM
```

> **Lưu ý thực tế:** Any.Run gói Free giới hạn ~14 task/tháng. Để demo không giới hạn → dùng nút **Demo Emotet** (không tốn quota).

---

## Luu y quan trong cho tai khoan Any.Run Free/Community

Luong API trong chuong trinh duoc giu nhu mot che do nang cao. Voi tai khoan Any.Run Free/Community, cach bam de va kha thi hon la:

1. Phan tich file/URL truc tiep tren giao dien web Any.Run.
2. Ghi lai public task URL, verdict, IOC, MITRE ATT&CK, process/network behavior.
3. Tai file Results `.md`. Neu tai khoan cho phep export JSON summary/IOC thi co the dung JSON.
4. Import vao tool bang:

```bash
python -X utf8 main.py --report-json Results.md
```

Hoac dung Web GUI -> tab **Import Report**.

Neu Any.Run chi cho copy IOC/hash tren giao dien, dan phan do vao o **Thong tin copy them tu Any.Run** khi import. CLI co the luu phan copy vao file `.txt` va chay:

```bash
python -X utf8 main.py --report-json Results.md --notes copied_iocs.txt
```

Neu khong co IOC JSON rieng, chuong trinh se tu suy ra IOC tu Results markdown/JSON summary: network connections, HTTP/DNS, hash, filename va MITRE ID neu co. File Get Sample `.bin` la mau ma doc/doi tuong phan tich, khong dung de import vao tool nay va khong nen mo/chay tren may that. Xem them tai lieu dinh huong do an tai `DO_AN_FREE_ANYRUN_IR.md`.

---

## Train ML khi tai khoan Any.Run bi gioi han

`train_ml.py` khong con chi tao du lieu gia lap. Script se gom du lieu theo thu tu:

1. `data/ml_training_seed.json`: seed dataset da chuan hoa 11 feature hanh vi.
2. Demo Any.Run noi bo: Emotet, WannaCry, RedLine.
3. `reports/analysis_history.json`: cac lan import/phan tich that ma app da luu.
4. `--synthetic N`: du lieu synthetic bo sung neu can can bang lop.

Train model:

```bash
python -X utf8 train_ml.py --synthetic 60
```

Output:

```text
models/rf_threat_model.pkl
models/rf_threat_model.meta.json
```

Luu y: dataset seed nay la bootstrap cho do an va demo IR, khong phai benchmark hoc thuat. Khi co them Any.Run Results `.md`/JSON public hoac report tu lich su local, hay import vao app de `analysis_history.json` lon dan roi train lai.

---

## Cau hinh AI Agent voi Ollama

AI Agent chi tra loi trong pham vi Incident Response/malware. Cau hoi ngoai pham vi se bi chan boi scope guardrail.

Neu muon dung Ollama local:

```bash
ollama pull llama3.1:8b
```

Trong `.env`:

```env
AI_PROVIDER=ollama
AI_TEMPERATURE=0.25
AI_MAX_TOKENS=1100
AI_TIMEOUT=45
AI_RETRIES=2
AI_CONTEXT_LIMIT=12000
OLLAMA_ENABLED=1
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.1:8b
OLLAMA_TIMEOUT=120
OLLAMA_NUM_PREDICT=700
```

Neu muon dung OpenAI hoac endpoint OpenAI-compatible:

```env
AI_PROVIDER=openai
OPENAI_API_KEY=sk-...
OPENAI_API_BASE=https://api.openai.com/v1
OPENAI_MODEL=gpt-4o-mini
```

Backend co endpoint `GET /api/ai/status` de kiem tra provider, model, context limit va retry config ma khong lo lo API key. Khi LLM that loi hoac timeout, app tu fallback ve Local assistant de demo khong bi dung dot ngot.

Sau khi doi `.env`, restart Flask server de app nhan cau hinh moi.

---

## Checklist phat trien prototype do an

Trang thai uu tien hien tai: tap trung lam luong demo chay tot, co dau ra ro rang de trinh bay.

### Luong demo nen dung khi bao cao

1. Chay server:

```powershell
python app.py
```

2. Mo Web GUI tai `http://127.0.0.1:5000`.
3. Bam **Demo Emotet**, **Demo WannaCry** hoac **Demo RedLine** neu khong muon ton quota Any.Run.
4. Kiem tra cac trang:
   - **Tong quan**: threat level, MITRE, file, network, process.
   - **IR Playbook**: cac buoc phan ung su co theo NIST.
   - **IOC Blocklist**: IOC va lenh chan nhanh.
5. Xuat bao cao:
   - `Markdown`, `HTML`, `PDF`, `JSON` cho bao cao.
   - `IOC CSV`, `Splunk SPL`, `Elastic KQL`, `Sigma` cho SIEM/hunting.
6. Mo thu muc `reports/` de lay file dau ra.

### SIEM export prototype

Tinh nang SIEM trong ban prototype khong ket noi truc tiep den Splunk/ELK. Thay vao do, tool sinh cac artifact co the copy/import vao he thong:

| Dinh dang | File | Muc dich |
|-----------|------|----------|
| IOC CSV | `SIEM_csv_*.csv` | Feed IOC don gian cho Excel, SIEM, SOAR hoac script noi bo |
| Splunk SPL | `SIEM_splunk_*.spl` | Cau lenh search/hunt tren Splunk |
| Elastic KQL | `SIEM_elastic_*.kql` | Cau query cho Kibana/Elastic Security |
| Sigma | `SIEM_sigma_*.yml` | Rule hunting experimental co the chuyen doi sang SIEM khac |

Day la cach phu hop voi do an/prototype: de demo, de kiem thu, khong phu thuoc moi truong Splunk/ELK that.

### Lenh kiem thu truoc khi nop/demo

```powershell
python -m black reporter.py app.py siem_exporter.py tests
python -m flake8 validation.py anyrun_client.py app.py reporter.py siem_exporter.py tests
python -m pytest
```

Neu tat ca test pass, prototype da du on de demo luong chinh.

### Huong phat trien tiep theo

- Luu lich su bang SQLite thay cho `reports/analysis_history.json`.
- Them bo ngon ngu `vi/en` cho label giao dien va report.
- Tao Dockerfile de chay nhanh tren may khac.
- Ket noi that den Splunk/Elastic bang API sau khi da co moi truong SIEM.
- Bo sung them report mau benign/suspicious de demo truong hop it du lieu.
