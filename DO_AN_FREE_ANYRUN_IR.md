# Dinh huong do an: Quy trinh phan ung su co dua tren Any.Run Free

## 1. Danh gia hien trang

Chuong trinh hien tai da co khung tot cho mot do an phan tich ma doc:

- Co pipeline ro rang: Any.Run report -> parser -> IOC -> MITRE ATT&CK -> IR playbook -> export bao cao.
- Co hai giao dien: CLI va Web GUI.
- Co du lieu demo cho nhieu ho ma doc nhu Emotet, WannaCry, RedLine.
- Co phan sinh lenh ung cuu cu the cho Windows: chan IP, xoa persistence, quet Defender, thu thap bang chung.

Van de chinh la luong ban dau qua phu thuoc vao Any.Run API. Voi tai khoan Community/free, cach lam phu hop hon la:

1. Chay mau tren giao dien web Any.Run.
2. Ghi lai public task URL, verdict, IOC, MITRE, process/network behavior.
3. Tai file Results `.md`; neu tai khoan cho phep thi export them JSON summary/IOC.
4. Import du lieu vao tool nay de sinh playbook phan ung su co.

Nhu vay do an van dung "phan tich ma doc thuc te bang Any.Run", nhung khong bi sai ky thuat do yeu cau API tra phi.

## 2. Pham vi dung voi tai khoan free

Theo trang pricing cua ANY.RUN, goi Community la free, co public analyses, timeout 60 giay va gioi han file 16 MB. Trang nay cung the hien private analyses la tinh nang tra phi, va API REST nam trong nhom API/exports cua cac goi cao hon. Mot so tai lieu tich hop cua ben thu ba cung ghi ro free plan khong co API access.

Ket luan cho do an:

- Nen trinh bay API la "tuy chon nang cao", khong phai dieu kien bat buoc.
- Luong chinh cua do an nen la "manual Any.Run analysis + JSON import + IR automation".
- Khong upload file co du lieu nhay cam len free public sandbox.

Nguon tham khao:

- ANY.RUN plans: https://any.run/plans/
- ANY.RUN sandbox overview: https://any.run/
- ANY.RUN report export blog: https://any.run/cybersecurity-blog/malware-analysis-report/

## 3. Quy trinh de bao ve truoc hoi dong

### Phase A - Triage va chuan bi

Input cua tinh huong:

- File/URL nghi ngo tu email, endpoint alert, SIEM alert hoac threat intel.
- Neu la file noi bo co du lieu nhay cam, chi hash va metadata duoc dua len moi truong public; khong dua file that len free sandbox.

Viẹc can lam:

- Tinh MD5/SHA256.
- Ghi thoi gian phat hien, nguon canh bao, may bi anh huong.
- Chon mau demo/public malware de phan tich tren Any.Run.

### Phase B - Phan tich dong tren Any.Run

Thuc hien tren app.any.run:

- Tao task public voi file/URL nghi ngo hoac chon mot public report co san.
- Quan sat process tree, network, dropped files, registry, MITRE ATT&CK.
- Ghi lai task UUID va public report URL.
- Tai JSON summary/IOC neu co, hoac copy cac IOC tu giao dien.

### Phase C - Dua du lieu vao tool

Co ba cach:

- Web GUI: tab `Import Report`.
- CLI: `python -X utf8 main.py --report-json Results.md`.
- Neu co JSON: `python -X utf8 main.py --report-json report.json --ioc-json ioc.json`.
- Demo: dung Emotet/WannaCry/RedLine khi khong co mau that.

Neu khong co IOC JSON rieng, analyzer se tu suy ra IOC tu Results markdown hoac report summary:

- IP tu network connections.
- Domain/URL tu HTTP va DNS.
- Hash va filename tu main object va dropped files.
- MITRE ID, URL, IP, domain va Windows path bang regex tu markdown.

File `Get Sample .bin` la mau ma doc/doi tuong phan tich duoc tai ve tu ANY.RUN. Khong import file nay vao tool IR, khong doi duoi thanh `.exe`, va khong chay tren may that. Chi luu trong thu muc cach ly neu can lam bang chung.

### Phase D - Sinh playbook IR

Tool tao playbook theo NIST SP 800-61:

- Identification: xac nhan verdict, hash, Any.Run task, MITRE.
- Containment: co lap host, chan IP/domain, dung process nguy hiem.
- Eradication: xoa dropped files, persistence, quet Defender, kiem tra scheduled task/service.
- Recovery: patch, reset credential, bat lai firewall/Defender, dua host tro lai san xuat.
- Lessons Learned: cap nhat IOC/SIEM, rut kinh nghiem, training nguoi dung.

### Phase E - Bao cao

Output cua do an:

- Dashboard ket qua phan tich.
- IOC blocklist.
- Markdown report cho nguoi quan ly.
- JSON report cho SIEM/SOAR.

## 4. Diem moi da bo sung vao chuong trinh

- Them import Any.Run Results markdown/JSON cho Web GUI tai `/api/analyze/json`.
- Them CLI mode `--report-json` cho ca `.md` va `.json`, kem `--ioc-json` neu co.
- Parser khong con phu thuoc bat buoc vao IOC API; co the suy IOC tu report summary.
- Cap nhat dependencies thieu cho Flask va ML.

## 5. Cach demo tren lop

Kich ban de xuat:

1. Mo Any.Run public report cua mot mau ransomware hoac stealer.
2. Chi ra IOC, process tree, MITRE ATT&CK tren Any.Run.
3. Import JSON vao tool.
4. Mo tab Dashboard de giai thich hanh vi ma doc.
5. Mo tab IR Playbook de trinh bay quy trinh ung cuu.
6. Export Markdown/JSON lam bang chung dau ra.

Thong diep chinh: Any.Run dung de quan sat hanh vi thuc te cua ma doc; chuong trinh Python dung de chuan hoa ket qua do thanh quy trinh phan ung su co co the thuc thi.
