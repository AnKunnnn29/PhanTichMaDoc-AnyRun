# Case Studies & Demo Script - Any.Run Malware IR Tool

> Tai lieu nay dung de trinh bay phan mo rong cua do an: tu ket qua phan tich ma doc tren Any.Run sang quy trinh Incident Response, scope hunting va detection engineering.

## 1. Muc tieu demo

Muc tieu cua buoi demo khong chi la cho thay tool doc duoc IOC, ma la chung minh mot luong lam viec gan voi SOC/IR thuc te:

1. Lay du lieu phan tich dong tu Any.Run hoac file Results export.
2. Chuan hoa IOC, MITRE ATT&CK, process, file, registry va network behavior.
3. Sinh playbook Incident Response theo cac pha NIST SP 800-61.
4. Tao timeline dieu tra va cau hoi scope hunting de tim host/user bi anh huong.
5. Xuat detection artifacts cho SIEM/EDR/NDR: Splunk, Elastic, Sentinel, Sigma, Suricata, STIX va IOC CSV.
6. Danh gia do san sang cua report bang IR readiness score.

Thong diep chinh: Any.Run giup quan sat hanh vi thuc te cua ma doc; tool Python bien quan sat do thanh hanh dong ung cuu va detection co the dua vao van hanh.

## 2. Bang so sanh case study

| Case | Loai ma doc | Input demo | Threat level | Risk score | MITRE | IOC | IR actions | Timeline | Hunting queries | Readiness |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Emotet | Trojan / downloader / banking malware | `Invoice_2024_Q4.doc` | 2/4 | 100/100 | 12 | 23 | 13 | 6 | 5 | 100% |
| WannaCry | Ransomware | `WannaCry_Payload.exe` | 4/4 | 100/100 | 5 | 13 | 8 | 6 | 4 | 100% |
| RedLine Stealer | Infostealer | `Crack_GTA5_Setup.exe` | 3/4 | 100/100 | 4 | 7 | 9 | 5 | 3 | 100% |

Ghi chu: threat level la ket qua sandbox/phan tich mau; risk score la ma tran noi bo cua tool, tinh them C2, persistence, process injection, dropped files, credential theft, exfiltration va ransomware impact.

## 3. Case study 1 - Emotet

### Tinh huong

SOC nhan canh bao email phishing co file dinh kem `Invoice_2024_Q4.doc`. File duoc dua vao Any.Run de quan sat hanh vi dong. Ket qua cho thay tai lieu Office kich hoat PowerShell, drop DLL va inject vao tien trinh hop le.

### Quan sat chinh

| Nhom du lieu | Gia tri tieu bieu |
|---|---|
| File chinh | `Invoice_2024_Q4.doc` |
| Process chain | `winword.exe` -> `powershell.exe` -> `rundll32.exe` |
| Injected process | `rundll32.exe`, `svchost.exe` |
| C2/domain | `malicious-c2.ru`, `evil-dropper.net`, `botnet-panel.top` |
| Dropped files | `payload.dll`, `svchost32.exe`, `updater.lnk` |
| Persistence | Run/RunOnce registry keys |
| MITRE noi bat | `T1566.001`, `T1059.001`, `T1055.001`, `T1547.001`, `T1041`, `T1071.001` |

### Dieu tra va phan ung su co

| Pha IR | Hanh dong |
|---|---|
| Identification | Luu Any.Run task, hash file, process tree va IOC. |
| Containment | Co lap endpoint, block IP/domain C2, dung process bi inject sau khi thu thap memory neu can. |
| Eradication | Xoa dropped files, go Run/RunOnce keys, quet AV/EDR full scan. |
| Recovery | Reset credential nguoi dung lien quan, cap nhat Office/Windows, dua may ve mang sau khi sach IOC. |
| Lessons Learned | Cap nhat email gateway rule, SIEM detection, IOC feed va training phishing. |

### Hunting queries can demo

| Cau hoi | Nguon log |
|---|---|
| Host nao tung ket noi toi C2 domain/IP? | DNS, proxy, firewall, EDR network telemetry |
| User nao da mo file Office hoac chay PowerShell encoded command? | EDR process telemetry |
| May nao co `payload.dll`, `svchost32.exe` hoac hash IOC? | EDR file telemetry |
| Mailbox nao nhan cung attachment/hash/sender? | Email gateway / M365 |

### Diem nhan khi thuyet trinh

Emotet la case phu hop de chung minh chuoi tan cong day du: phishing -> execution -> injection -> persistence -> C2/exfiltration -> IR playbook -> detection output.

## 4. Case study 2 - WannaCry

### Tinh huong

SOC phat hien endpoint co dau hieu ransomware va file `WannaCry_Payload.exe`. Mau duoc phan tich trong sandbox de xac dinh impact va cac hanh vi pha hoai co che khoi phuc.

### Quan sat chinh

| Nhom du lieu | Gia tri tieu bieu |
|---|---|
| File chinh | `WannaCry_Payload.exe` |
| Process | `WannaCry_Payload.exe`, `cmd.exe`, `tasksche.exe` |
| Lenh nguy hiem | `vssadmin.exe Delete Shadows /All /Quiet`, `bcdedit /set {default} recoveryenabled No` |
| Domain kill-switch | `www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com` |
| Port noi bo | SMB/445 trong demo network |
| MITRE noi bat | `T1486`, `T1490`, `T1059.003`, `T1543.003`, `T1012` |

### Dieu tra va phan ung su co

| Pha IR | Hanh dong |
|---|---|
| Identification | Xac nhan ransomware, ghi lai hash, ransom note va command line. |
| Containment | Co lap may ngay lap tuc, uu tien ngat LAN/SMB, bao ve backup offline. |
| Eradication | Dung process ma hoa, kiem tra service/task, xoa dropped executable. |
| Recovery | Khong khoi phuc tu backup online chua kiem tra; quet backup offline truoc khi restore. |
| Lessons Learned | Cap nhat patch SMB, rule canh bao vssadmin/bcdedit bat thuong, quy trinh ransomware. |

### Hunting queries can demo

| Cau hoi | Nguon log |
|---|---|
| Host nao goi `vssadmin delete shadows` hoac `bcdedit recoveryenabled No`? | EDR process telemetry |
| Host nao ket noi SMB/445 bat thuong cung thoi diem? | Firewall/NDR/Windows event log |
| May nao tao file ransom note hoac `tasksche.exe`? | EDR file telemetry |
| Backup nao bi truy cap/chinh sua gan thoi diem su co? | Backup system audit log |

### Diem nhan khi thuyet trinh

WannaCry la case tot de trinh bay su khac nhau giua response thong thuong va response khan cap: co lap truoc, bao ve backup, khong voi vang recovery khi chua xac dinh pham vi.

## 5. Case study 3 - RedLine Stealer

### Tinh huong

Nguoi dung tai file crack `Crack_GTA5_Setup.exe`. Sandbox cho thay hanh vi infostealer: process injection, credential access, keylogging va exfiltration qua C2.

### Quan sat chinh

| Nhom du lieu | Gia tri tieu bieu |
|---|---|
| File chinh | `Crack_GTA5_Setup.exe` |
| Process | `Crack_GTA5_Setup.exe`, `InstallUtil.exe` |
| Injected process | `InstallUtil.exe` |
| C2/IP | `185.112.83.11` |
| Dropped file | `log.txt` |
| MITRE noi bat | `T1552.001`, `T1056.001`, `T1082`, `T1041` |

### Dieu tra va phan ung su co

| Pha IR | Hanh dong |
|---|---|
| Identification | Xac dinh stealer, ghi lai tai khoan nguoi dung va ung dung da dang nhap tren host. |
| Containment | Co lap endpoint, block C2 IP, thu thap EDR/process/file artifact. |
| Eradication | Xoa dropped file, scan host, kiem tra startup/persistence neu co. |
| Recovery | Reset password, revoke token/session, bat MFA, kiem tra browser credential store. |
| Lessons Learned | Chan software crack, canh bao download source, them detection cho infostealer. |

### Hunting queries can demo

| Cau hoi | Nguon log |
|---|---|
| Host nao ket noi toi `185.112.83.11`? | Firewall/proxy/EDR network |
| User nao chay file crack hoac `InstallUtil.exe` bat thuong? | EDR process telemetry |
| Token/session nao can revoke sau khi nghi ngo credential theft? | IAM/SSO/M365/Azure AD logs |

### Diem nhan khi thuyet trinh

RedLine giup trinh bay diem quan trong cua IR: voi stealer, xoa malware chua du; phai xu ly credential, token, session va hunting dang nhap bat thuong sau su co.

## 6. Kich ban demo tren lop

### Buoc 1 - Gioi thieu bai toan

Noi ngan gon:

> Khi co file/URL nghi ngo, Any.Run cho ta hanh vi dong. Van de la SOC can bien hanh vi do thanh quy trinh ung cuu: co lap, hunt, xoa, phuc hoi va tao rule phong thu.

### Buoc 2 - Chay demo trong Web GUI

1. Chay server: `python app.py`.
2. Mo `http://127.0.0.1:5000/`.
3. Chon demo `Emotet`, `WannaCry` hoac `RedLine`.
4. Vao Dashboard de chi ra verdict, file, MITRE, C2, dropped files.
5. Vao IR Playbook de chi ra:
   - Risk score.
   - Timeline dieu tra.
   - Scope & Threat Hunting.
   - Owner/SLA/evidence cho tung action.
6. Vao IOC tab de export:
   - IOC CSV.
   - Splunk SPL.
   - Elastic KQL.
   - Sentinel KQL.
   - Sigma.
   - Suricata rules.
   - STIX 2.1 bundle.

### Buoc 3 - Giai thich output

| Output | Dung cho ai | Muc dich |
|---|---|---|
| Markdown/HTML/PDF | Quan ly, giang vien, IR lead | Bao cao su co co cau truc |
| JSON | Tich hop tool khac | Luu payload co cau truc |
| IOC CSV | Firewall/EDR/threat intel | Import blocklist nhanh |
| Splunk SPL | SOC dung Splunk | Hunt host/user cham IOC |
| Elastic KQL | SOC dung Elastic | Hunt theo ECS fields |
| Sentinel KQL | Microsoft Defender/Sentinel | Hunt network/file events |
| Sigma | Detection engineering | Chuyen doi sang SIEM rule |
| Suricata | NDR/IDS | Canh bao DNS/HTTP/IP IOC |
| STIX 2.1 | Threat intelligence sharing | Chia se IOC theo chuan |

### Buoc 4 - Ket luan

Noi ngan gon:

> Diem moi cua do an la khong dung sandbox nhu mot man hinh xem ket qua, ma dung no lam dau vao cho mot quy trinh IR co the van hanh: co scoring, timeline, scope hunting, owner/SLA, evidence va detection output.

## 7. Cau hoi hoi dong co the hoi

### Vi sao khong dua file that noi bo len Any.Run free?

Vi phan tich free/public sandbox co the cong khai mau va metadata. Voi file noi bo nhay cam, chi nen dua hash/metadata hoac dung mau public/demo; neu can phan tich file that thi dung moi truong private/enterprise hoac sandbox noi bo.

### IOC co du de ket luan may da sach khong?

Khong. IOC chi la dau hieu quan sat duoc. Dieu kien sach can gom: khong con process/dropped file/persistence, EDR/AV scan sach, log DNS/proxy/firewall khong con ket noi IOC moi, va tai khoan lien quan da duoc xu ly neu co dau hieu stealer.

### Vi sao risk score co the CRITICAL trong khi Any.Run threat level chi HIGH?

Any.Run threat level danh gia mau trong sandbox. Risk score cua tool danh gia them tac dong van hanh: C2, injection, persistence, exfiltration, credential theft va ransomware. Trong IR, mot mau co threat level trung binh-cao van co the thanh critical neu anh huong credential, C2 hoac nhieu host.

### Detection output co chay truc tiep duoc khong?

Dung nhu baseline/hunt query ban dau. Truoc khi dua vao production, SOC can review false positive, map field theo schema log cua minh, test tren du lieu that va gan owner cho rule.

## 8. Checklist truoc khi bao ve

- Chay `python -m pytest -q` va chup ket qua pass.
- Chay Web GUI, demo it nhat 2 case: Emotet va WannaCry hoac RedLine.
- Export mot report Markdown/PDF.
- Export it nhat 3 detection artifacts: Sentinel KQL, Sigma, Suricata/STIX.
- Giai thich ro gioi han Any.Run free/public.
- Chuan bi cau tra loi ve IOC, false positive, privacy va scope hunting.
