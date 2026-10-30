"""Case-specific response actions built from the network profiles and impact facts of one case.

Every action names its exact targets (hash, IP:port, task name, registry value, exclusion path,
file extension) and comes with a query to confirm the target on real hosts first. Commands are
references for an analyst to adapt; nothing here is executed.
"""
from __future__ import annotations

import re
from pathlib import PureWindowsPath

from incident_response import IncidentAction, IncidentResponseGenerator

PHASE = IncidentResponseGenerator.PHASES
BLOCK_ROLES = {"config_c2", "known_c2", "malware_distribution", "malicious_reported", "payload_download"}


def _ps(value: str) -> str:
    """Single-quoted PowerShell literal."""
    return "'" + str(value).replace("'", "''") + "'"


def _kql_list(values) -> str:
    return ", ".join('"' + str(v).replace('"', '\\"') + '"' for v in values)


def _action(profile, phase, priority, category, title, objective, targets, verify_first, steps, verification,
            rollback, commands, evidence_ids):
    action = IncidentAction(priority=priority, phase=PHASE[phase], category=category, title=title,
                            description=objective, commands=commands)
    action.response_profile = profile
    action.objective = objective
    action.target_scope = ("Đối tượng: " + "; ".join(targets[:8]) + ("; …" if len(targets) > 8 else "")
                           + ". Chưa xác minh endpoint thực tế: tên tệp, PID và IOC lấy từ sandbox.")
    action.preconditions = verify_first
    action.steps = steps
    action.verification = verification
    action.rollback = rollback
    action.risks = [rollback]
    action.evidence_ids = list(dict.fromkeys(evidence_ids))[:20]
    action.origin = "case_specific"
    return action


def _hashes(report) -> tuple[list[str], list[str]]:
    content = report["data"]["content"]
    main = str(((content.get("mainObject") or {}).get("hashes") or {}).get("sha256", "")).lower()
    dropped = []
    for d in content.get("dropped") or []:
        name = PureWindowsPath(str(d.get("filename", ""))).name
        sha = str((d.get("hashes") or {}).get("sha256", "")).lower()
        executable = d.get("type") == "executable" or name.lower().rsplit(".", 1)[-1] in {"exe", "dll", "scr", "bat", "ps1", "vbs", "js"}
        if executable and re.fullmatch(r"[0-9a-f]{64}", sha) and not name.startswith("__PSScriptPolicyTest_"):
            dropped.append(sha)
    main_list = [main] if re.fullmatch(r"[0-9a-f]{64}", main) else []
    return main_list, list(dict.fromkeys(h for h in dropped if h not in main_list))[:20]


def _category(impact, cid):
    return next((c for c in impact.get("categories", []) if c["id"] == cid), None)


def build_case_actions(report: dict, impact: dict, profiles: dict, threat: dict) -> list[IncidentAction]:
    actions = []
    content = report["data"]["content"]
    family = str(threat.get("threat_name") or "").strip() or "mã độc"
    main_hash, dropped_hashes = _hashes(report)
    all_hashes = main_hash + dropped_hashes
    sample_ids = [e for c in impact.get("categories", []) for e in c["evidence_ids"][:2]]

    # 1. Find the real infected hosts: everything else depends on this.
    if all_hashes:
        names = [PureWindowsPath(str((content.get("mainObject") or {}).get("filename", ""))).name] if main_hash else []
        actions.append(_action(
            "triage", "IDENTIFY", 1, "Hunting", f"Tìm máy nhiễm {family} trong tổ chức theo hash",
            "Xác định máy thật đã chạy hoặc lưu mẫu, trước mọi thao tác thay đổi hệ thống.",
            [f"SHA256 mẫu chính {main_hash[0]}" if main_hash else "Không có SHA256 mẫu chính"]
            + [f"{len(dropped_hashes)} SHA256 tệp thực thi do mẫu tạo ra"] if dropped_hashes else
            [f"SHA256 mẫu chính {main_hash[0]}" if main_hash else "Không có SHA256 mẫu chính"],
            ["Chạy truy vấn bên dưới trên EDR/SIEM, phạm vi ít nhất 30 ngày.",
             "Ghi lại DeviceName, tài khoản, thời điểm và đường dẫn của mọi kết quả khớp."],
            ["Lập danh sách máy khớp hash và mức độ: chỉ lưu tệp / đã thực thi.",
             "Với mỗi máy đã thực thi: áp dụng các bước ngăn chặn bên dưới cho đúng máy đó.",
             "Lưu truy vấn và kết quả làm bằng chứng của hồ sơ."],
            ["Có danh sách máy (hoặc ghi rõ không tìm thấy) kèm truy vấn đã dùng.",
             "Mọi máy đã thực thi mẫu đều đã được chuyển sang bước ngăn chặn."],
            "Bước tra cứu không thay đổi hệ thống; không cần hoàn tác.",
            ["// Microsoft Defender XDR / Sentinel",
             f"DeviceFileEvents | where SHA256 in ({_kql_list(all_hashes)})"
             " | summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Paths=make_set(FolderPath) by DeviceName, SHA256",
             f"DeviceProcessEvents | where SHA256 in ({_kql_list(all_hashes)}) or FileName in~ ({_kql_list(names)})"
             " | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine",
             "# Một máy cụ thể (PowerShell):",
             f"Get-ChildItem C:\\Users -Recurse -File -ErrorAction SilentlyContinue | Get-FileHash | Where-Object Hash -in @({', '.join(_ps(h.upper()) for h in all_hashes[:10])})"],
            sample_ids))

    # 2. Network: block only evidenced destinations, keep the kill switch reachable, never block whitelisted traffic.
    notable = [p for p in profiles.values() if p["role"] in BLOCK_ROLES]
    if notable:
        ips = [p["value"] for p in notable if p["type"] == "ip"]
        domains = [p["value"] for p in notable if p["type"] == "domain"]
        urls = [p["value"] for p in notable if p["type"] == "url"]
        endpoints = [f"{p['value']}" + (f" (port {', '.join(map(str, p['ports']))})" if p["ports"] else "") + f" – {p['meaning']}" for p in notable]
        commands = ["// Xác minh trước: máy nào trong tổ chức đã kết nối?",
                    "DeviceNetworkEvents | where " + " or ".join(filter(None, [f"RemoteIP in ({_kql_list(ips)})" if ips else "",
                                                                              f"RemoteUrl has_any ({_kql_list(domains + urls)})" if domains or urls else ""]))
                    + " | summarize Connections=count(), LastSeen=max(Timestamp) by DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort"]
        commands += [f'netsh advfirewall firewall add rule name="IR_block_{ip}" dir=out action=block remoteip={ip}' for ip in ips]
        commands += [f"# Chặn domain tại DNS/proxy (không chỉ trên một máy): {d}" for d in domains + urls]
        actions.append(_action(
            "network", "CONTAIN", 1, "Mạng", f"Chặn {len(notable)} đích tấn công đã xác định của {family}",
            "Cắt liên lạc giữa máy nhiễm và hạ tầng của kẻ tấn công; chỉ áp dụng cho đích có bằng chứng.",
            endpoints,
            ["Chạy truy vấn DeviceNetworkEvents để biết máy nào đã kết nối; các máy đó là máy nhiễm cần xử lý.",
             "Kiểm tra đích không phải dịch vụ dùng chung của tổ chức (CDN, cloud) trước khi chặn."],
            [f"Chặn tại firewall biên/proxy: {', '.join(p['value'] for p in notable[:6])}.",
             "Ưu tiên chặn tập trung (firewall, proxy, DNS sinkhole) thay vì từng máy.",
             "Ghi mã thay đổi và thời hạn của quy tắc chặn."],
            ["Log firewall/proxy ghi nhận kết nối bị chặn tới đúng các đích trên.",
             "Không còn kết nối mới tới các đích này sau khi chặn."],
            "Gỡ đúng quy tắc vừa tạo (tên bắt đầu IR_block_) nếu ảnh hưởng dịch vụ hợp lệ.",
            commands, [i for p in notable for i in p["evidence_ids"][:2]]))
    kill = [p for p in profiles.values() if p["role"] == "kill_switch"]
    if kill:
        actions.append(_action(
            "network", "CONTAIN", 1, "Mạng", "Giữ domain kill-switch WannaCry truy cập được",
            "Kill-switch làm WannaCry dừng mã hóa; chặn nó có thể làm mã độc tiếp tục hoạt động.",
            [p["value"] for p in kill],
            ["Kiểm tra DNS/proxy hiện không chặn các domain này."],
            ["Đảm bảo domain phân giải và truy cập được từ mạng nội bộ.",
             "Thêm ngoại lệ cho domain kill-switch trong mọi danh sách chặn tự động/threat feed.",
             "Dùng log DNS truy vấn domain để tìm máy đã nhiễm."],
            ["Resolve-DnsName và kết nối HTTP tới domain thành công từ mạng nội bộ."],
            "Không áp dụng chặn cho domain này.",
            [f"Resolve-DnsName {_ps(p['value'])}" for p in kill] +
            ["DeviceNetworkEvents | where RemoteUrl has_any (" + _kql_list(p["value"] for p in kill) + ") | summarize by DeviceName"],
            [i for p in kill for i in p["evidence_ids"][:2]]))
    if profiles and not notable and not kill:
        benign = [p for p in profiles.values() if p["role"] in {"benign_infrastructure", "local_network"}]
        actions.append(_action(
            "network", "CONTAIN", 3, "Mạng", "Không chặn mạng: lưu lượng sandbox là hạ tầng hợp lệ",
            "Tránh chặn nhầm dịch vụ Windows/Microsoft/CDN mà sandbox ghi nhận.",
            [f"{len(benign)} đích whitelisted hoặc mạng nội bộ sandbox"],
            ["Xác nhận lại không có đích nào ngoài whitelist do chính tiến trình mẫu kết nối."],
            ["Không tạo quy tắc chặn IP/domain từ báo cáo này.",
             "Tập trung ngăn chặn ở mức máy (cô lập máy nhiễm) thay vì chặn mạng.",
             "Nếu log của tổ chức cho thấy đích độc hại mới, lập khuyến nghị chặn riêng cho đích đó."],
            ["Danh sách chặn không chứa đích hợp lệ của Microsoft/CDN."],
            "Không có thay đổi mạng để hoàn tác.", [], [i for p in benign[:3] for i in p["evidence_ids"][:1]]))
    spread = _category(impact, "lateral_spread")
    if spread:
        actions.append(_action(
            "network", "CONTAIN", 1, "Mạng", "Chặn lây lan SMB và vá MS17-010",
            "Ngăn mã độc lây sang máy Windows khác trong mạng nội bộ qua SMB.", spread["facts"],
            ["Tìm máy nhận kết nối 445 từ máy nhiễm trong log firewall nội bộ."],
            ["Chặn TCP 445/139 giữa các phân đoạn máy trạm; chỉ mở tới máy chủ tệp cần thiết.",
             "Kiểm tra và cài bản vá MS17-010 trên mọi máy Windows; tắt SMBv1.",
             "Đưa các máy đã nhận kết nối SMB từ máy nhiễm vào danh sách hunting theo hash."],
            ["Get-HotFix cho thấy bản vá; SMBv1 đã tắt trên máy đã kiểm tra.", "Không còn lưu lượng 445 bất thường từ máy nhiễm."],
            "Mở lại 445 có kiểm soát cho dịch vụ tệp hợp lệ nếu bị gián đoạn.",
            ["Get-SmbServerConfiguration | Select EnableSMB1Protocol",
             "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
             "Get-HotFix | Where-Object HotFixID -in 'KB4012212','KB4012215','KB4012598','KB4013429'"],
            spread["evidence_ids"]))

    # 3. Ransomware: isolate without destroying evidence, then restore from offline backup.
    enc = _category(impact, "data_encryption")
    if enc:
        markers = re.findall(r"\.([A-Z0-9]{3,12}) \(\d+\)", enc["facts"][0])
        notes = sorted(set(re.findall(r"@?[\w@.-]*(?:read_?me|decrypt|restore|recover)[\w@.-]*\.(?:txt|html?|hta)", " ".join(enc["facts"]), re.I)))
        actions.append(_action(
            "network", "CONTAIN", 1, "Ransomware", "Cô lập máy đang bị mã hóa, giữ nguyên nguồn điện",
            "Dừng mã hóa lan sang ổ mạng và máy khác, đồng thời giữ bộ nhớ để điều tra.",
            enc["facts"][:3],
            ["Xác nhận máy có tệp đuôi " + ", ".join("." + m for m in markers) + " (truy vấn bên dưới)."],
            ["Cô lập máy qua EDR (network isolation), không rút điện/tắt máy.",
             "Thu thập bộ nhớ (memory dump) trước khi khởi động lại.",
             "Ngắt ánh xạ ổ mạng của tài khoản trên máy nhiễm; kiểm tra thư mục chia sẻ có tệp cùng đuôi."],
            ["EDR báo máy ở trạng thái isolated.", "Không còn tệp mới có đuôi mã hóa xuất hiện trên share."],
            "Bỏ cô lập chỉ khi IR lead xác nhận máy đã được xử lý hoặc reimage.",
            ["DeviceFileEvents | where " + " or ".join(f'FileName endswith "{"." + m}"' for m in markers)
             + " | summarize Files=count() by DeviceName, FolderPath" if markers else "// Không xác định được đuôi mã hóa",
             "# Trên thư mục chia sẻ:",
             "Get-ChildItem '\\\\<file-server>\\<share>' -Recurse -File -Include " + ",".join("*." + m for m in markers) + " | Group-Object Directory | Select Count, Name"
             if markers else "",
             *[f"Get-ChildItem C:\\ -Recurse -Filter {_ps(n)} -ErrorAction SilentlyContinue" for n in notes[:2]]],
            enc["evidence_ids"]))
        rec = _category(impact, "recovery_inhibition")
        actions.append(_action(
            "recover", "RECOVER", 1, "Ransomware", "Khôi phục dữ liệu bị mã hóa từ bản sao lưu ngoại tuyến",
            "Lấy lại dữ liệu người dùng mà không trả tiền chuộc.",
            [f for f in enc["facts"] if f.startswith(("Loại tệp gốc", "Thư mục bị ảnh hưởng"))],
            ["Xác định thời điểm mã hóa đầu tiên để chọn bản sao lưu trước thời điểm đó.",
             "Kiểm tra bản sao lưu không bị mã hóa và không chứa mẫu (quét theo hash)."],
            ["Reimage máy trước khi khôi phục dữ liệu (xem bước loại bỏ).",
             "Khôi phục các thư mục bị ảnh hưởng đã liệt kê từ bản sao lưu ngoại tuyến/immutable.",
             "Không mở hay chạy lại các tệp ghi chú tiền chuộc và tệp đã mã hóa trên máy sạch."]
            + (["Shadow copy đã bị xóa (bằng chứng: " + rec["facts"][0][:120] + ") nên không dùng được System Restore."] if rec
               else ["Kiểm tra shadow copy còn không (vssadmin list shadows) nhưng không dựa vào nó."]),
            ["Người dùng xác nhận mở được tệp đã khôi phục.", "Quét lại dữ liệu khôi phục không có hash của mẫu."],
            "Giữ bản sao dữ liệu đã mã hóa riêng biệt; có thể giải mã sau nếu có công cụ công khai.",
            ["vssadmin list shadows", "# Kiểm tra công cụ giải mã công khai: https://www.nomoreransom.org/"],
            enc["evidence_ids"] + (rec["evidence_ids"] if rec else [])))

    # 4. Persistence: remove exactly the entries the sample created.
    per = _category(impact, "persistence")
    if per:
        commands = []
        for fact in per["facts"]:
            task = re.match(r'Scheduled task "([^"]+)"', fact)
            if task:
                commands += [f"schtasks /Query /TN {_ps(task.group(1))} /V /FO LIST > task_{len(commands)}.txt",
                             f"schtasks /Delete /TN {_ps(task.group(1))} /F"]
            reg = re.match(r"Registry (.+)\\([^\\=]+) = ", fact)
            if reg:
                commands += [f'reg export "{reg.group(1)}" run_backup.reg /y', f'reg delete "{reg.group(1)}" /v "{reg.group(2).strip()}" /f']
        startup = [f for f in per["facts"] if "thư mục Startup" in f]
        if startup:
            commands += ["Get-ChildItem \"$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\" | Get-FileHash"]
        actions.append(_action(
            "persistence", "ERADICATE", 1, "Persistence", "Gỡ các cơ chế tự khởi động mà mẫu đã tạo",
            "Ngăn mã độc tự chạy lại sau khi đăng nhập hoặc khởi động lại.", per["facts"],
            ["Trên máy nhiễm: xác nhận từng task/registry/tệp Startup trên tồn tại và trỏ tới tệp độc hại (so SHA256)."],
            ["Xuất cấu hình từng task/registry trước khi xóa (lệnh Query/export bên dưới).",
             "Xóa đúng các task và value đã liệt kê; quarantine tệp trong thư mục Startup qua EDR.",
             "Đăng xuất/đăng nhập lại rồi kiểm tra không có task/tệp nào được tạo lại."],
            ["schtasks /Query không còn các task trên; thư mục Startup không còn tệp độc hại.",
             "Autoruns không còn mục trỏ tới đường dẫn của mẫu."],
            "Khôi phục từ tệp export nếu xóa nhầm mục hợp lệ; nếu mục độc hại tự tạo lại, cô lập máy và chuyển sang reimage.",
            commands or ["# Dùng Autoruns (Sysinternals) để đối chiếu các mục trên"], per["evidence_ids"]))

    # 5. Defence impairment: undo the exact exclusions and permissions.
    evasion = _category(impact, "defense_impairment")
    if evasion:
        paths = [m.group(1).strip() for f in evasion["facts"] for m in [re.match(r"Thêm vào danh sách loại trừ Defender: (.+?)(?: \(toàn bộ.*)?$", f)] if m]
        commands = ["Get-MpPreference | Select-Object -ExpandProperty ExclusionPath"]
        for path in paths:
            if path.startswith("@("):
                commands += ["Remove-MpPreference -ExclusionPath $env:UserProfile", "Remove-MpPreference -ExclusionPath $env:SystemDrive"]
            else:
                commands.append(f"Remove-MpPreference -ExclusionPath {_ps(path)}")
        commands += ["Update-MpSignature", "Start-MpScan -ScanType FullScan"]
        actions.append(_action(
            "eradicate", "ERADICATE", 1, "Phòng thủ", "Gỡ loại trừ Defender và khôi phục cấu hình bảo vệ",
            "Đưa các vị trí mã độc đã loại trừ trở lại phạm vi quét trước khi kết luận máy sạch.", evasion["facts"],
            ["Chạy Get-MpPreference trên máy nhiễm để xác nhận đúng các exclusion trên đang tồn tại.",
             "Kiểm tra GPO/Intune có đặt exclusion hợp lệ nào trùng không."],
            [f"Xóa {len(paths)} exclusion đã liệt kê.",
             "Khôi phục ACL/thuộc tính tệp đã bị đổi (icacls/attrib) ở các thư mục liên quan.",
             "Cập nhật chữ ký và quét toàn bộ máy."],
            ["Get-MpPreference không còn các exclusion trên.", "Quét đầy đủ hoàn tất; mọi phát hiện đã xử lý."],
            "Thêm lại exclusion hợp lệ của tổ chức (nếu có) theo danh sách đã được phê duyệt.",
            commands, evasion["evidence_ids"]))

    # 6. Dropped payloads and the rebuild decision.
    drop = _category(impact, "payload_drop")
    theft = _category(impact, "credential_theft")
    if drop or enc or theft:
        reimage = bool(enc or theft or per)
        actions.append(_action(
            "eradicate", "ERADICATE", 1 if reimage else 2, "Loại bỏ",
            "Reimage máy nhiễm" if reimage else "Quarantine các tệp do mẫu tạo ra",
            ("Mẫu đã " + ", ".join(x for x, c in (("mã hóa dữ liệu", enc), ("đánh cắp thông tin", theft), ("tạo cơ chế tự khởi động", per)) if c)
             + " nên không thể chứng minh máy sạch chỉ bằng xóa tệp; dựng lại từ image tin cậy.") if reimage
            else "Loại bỏ các tệp thực thi mà mẫu đã thả.",
            drop["facts"] if drop else [f"{family} trên các máy đã xác định ở bước hunting"],
            ["Đã thu thập bộ nhớ, log và tệp mẫu cần cho điều tra."],
            (["Quarantine qua EDR theo SHA256 các tệp đã liệt kê (giữ bằng chứng thay vì xóa).",
              "Reimage từ image tin cậy; không sao chép lại tệp thực thi, task hay cấu hình từ máy nhiễm.",
              "Cài bản vá và EDR cho máy mới trước khi nối lại mạng."] if reimage else
             ["Quarantine qua EDR theo SHA256 các tệp đã liệt kê.", "Quét lại toàn máy sau khi quarantine.",
              "Theo dõi máy trong cửa sổ đã thống nhất để phát hiện tệp được tạo lại."]),
            ["Hash các tệp trên không còn xuất hiện trên máy (DeviceFileEvents).", "Máy mới không có cơ chế tự khởi động đã liệt kê."],
            "Giữ ổ đĩa/ảnh của máy cũ cho tới khi đóng hồ sơ.",
            [f"DeviceFileEvents | where SHA256 in ({_kql_list(dropped_hashes)}) | summarize by DeviceName, FolderPath"] if dropped_hashes else [],
            [i for c in (drop, enc, theft, per) if c for i in c["evidence_ids"][:5]]))

    # 7. Stolen data: reset what this family actually takes, from a clean device.
    if theft:
        kinds = sorted({k.strip() for f in theft["facts"] for k in (f.split("→")[1].split("(")[0].split(",") if "→" in f else [])})
        actions.append(_action(
            "identity", "CONTAIN", 1, "Tài khoản", "Thu hồi phiên và đổi thông tin đăng nhập bị lộ",
            "Vô hiệu hóa dữ liệu đăng nhập mà mẫu có thể đã gửi ra ngoài.",
            theft["facts"] + ([f"Loại dữ liệu: {', '.join(kinds)}"] if kinds else []),
            ["Liệt kê tài khoản đã đăng nhập trên máy nhiễm (trình duyệt, Windows, ứng dụng) trong 30 ngày.",
             "Kiểm tra đăng nhập bất thường của các tài khoản đó sau thời điểm nhiễm."],
            ["Từ máy sạch: đổi mật khẩu tài khoản doanh nghiệp và tài khoản đã lưu trong trình duyệt của máy nhiễm.",
             "Thu hồi mọi phiên/refresh token (cookie bị đánh cắp vẫn dùng được dù đã đổi mật khẩu).",
             "Nếu có ví tiền điện tử hoặc token ứng dụng (Discord, Telegram, VPN): chuyển tài sản/thu hồi token."],
            ["Nhật ký định danh có sự kiện thu hồi phiên và đổi mật khẩu.", "Không còn đăng nhập bất thường trong cửa sổ giám sát."],
            "Dùng quy trình khôi phục tài khoản đã xác thực nếu khóa nhầm; không khôi phục mật khẩu cũ.",
            ["# Microsoft Entra ID (Microsoft Graph PowerShell):", "Revoke-MgUserSignInSession -UserId <user@domain>",
             "SigninLogs | where UserPrincipalName == '<user@domain>' and TimeGenerated > ago(30d) | summarize by IPAddress, Location, AppDisplayName"],
            theft["evidence_ids"]))

    # 8. Detection follow-up for the techniques actually seen.
    execution = _category(impact, "execution")
    if execution or evasion:
        actions.append(_action(
            "lessons", "LESSONS", 3, "Phát hiện", "Thêm cảnh báo cho đúng kỹ thuật mẫu đã dùng",
            "Phát hiện sớm nếu cùng kỹ thuật xuất hiện lại ở máy khác.",
            (execution["facts"][:3] if execution else []) + (evasion["facts"][:2] if evasion else []),
            ["Kiểm thử truy vấn trên dữ liệu 30 ngày để ước lượng cảnh báo sai."],
            ["Bật PowerShell Script Block Logging (Event ID 4104) nếu chưa bật.",
             "Tạo cảnh báo cho các command line tương tự bên dưới.",
             "Lưu quy tắc vào kho detection kèm mã hồ sơ này để tham chiếu."],
            ["Truy vấn trả đúng các sự kiện của mẫu này và ít cảnh báo sai."],
            "Tắt hoặc tinh chỉnh quy tắc nếu gây quá nhiều cảnh báo sai.",
            ["DeviceProcessEvents | where ProcessCommandLine has_all ('Add-MpPreference', 'ExclusionPath')",
             "DeviceProcessEvents | where FileName =~ 'powershell.exe' and ProcessCommandLine has_any ('-EncodedCommand', '-enc ')",
             "DeviceProcessEvents | where FileName =~ 'schtasks.exe' and ProcessCommandLine has_all ('/Create', 'ONLOGON', 'HIGHEST')"],
            (execution["evidence_ids"] if execution else []) + (evasion["evidence_ids"][:3] if evasion else [])))
    for a in actions:
        a.commands = [c for c in a.commands if c]
    return actions


def merge_actions(template_actions: list, case_actions: list) -> list:
    """Case-specific actions replace templates of the same profile; uncovered templates stay, labelled."""
    covered = {a.response_profile for a in case_actions}
    kept = []
    for action in template_actions:
        if action.response_profile in covered and action.response_profile != "lessons":
            continue
        action.origin = "template"
        kept.append(action)
    return sorted(case_actions + kept, key=lambda a: (a.priority, list(PHASE.values()).index(a.phase) if a.phase in PHASE.values() else 9))
