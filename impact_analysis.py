"""Concrete impact facts from sandbox evidence: what was encrypted, stolen, persisted or disabled.

Each category lists observed facts with the evidence that shows them. Absence in the sandbox
is reported as "not observed", never as "did not happen" on a real host.
"""
from __future__ import annotations

import base64
import re
from collections import Counter
from pathlib import PureWindowsPath

USER_DATA_EXT = {"doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "rtf", "txt", "csv", "odt", "jpg", "jpeg", "png",
                 "gif", "bmp", "mp3", "mp4", "avi", "mov", "zip", "rar", "7z", "sql", "db", "mdb", "pst", "ost", "psd",
                 "dwg", "xml", "html", "py", "java", "cpp", "c", "cs", "php", "js", "json", "key", "pem", "pfx", "vsd"}
TEMP_EXT = {"tmp", "temp", "wncryt"}  # working copies written during encryption
RANSOM_NOTE = re.compile(r"(read_?me|readme|decrypt|how_to|restore|recover|ransom|@please|instructions?).*\.(txt|html?|hta|bmp|png|url)$",
                         re.IGNORECASE)
EXECUTABLE_EXT = {"exe", "dll", "scr", "sys", "bat", "cmd", "ps1", "vbs", "js", "jse", "hta", "msi", "lnk", "com", "pif"}
RECOVERY_PATTERNS = [(re.compile(r"vssadmin.*delete\s+shadows", re.I), "Xóa toàn bộ shadow copy bằng vssadmin"),
                     (re.compile(r"wmic.*shadowcopy.*delete", re.I), "Xóa shadow copy bằng WMIC"),
                     (re.compile(r"bcdedit.*recoveryenabled\s+no", re.I), "Tắt chế độ khôi phục Windows (bcdedit)"),
                     (re.compile(r"bcdedit.*bootstatuspolicy\s+ignoreallfailures", re.I), "Bỏ qua lỗi khởi động (bcdedit)"),
                     (re.compile(r"wbadmin.*delete\s+(catalog|systemstatebackup|backup)", re.I), "Xóa bản sao lưu Windows Backup (wbadmin)")]
STEAL_TERMS = {"steal": "đánh cắp dữ liệu", "credential": "thông tin đăng nhập", "browser": "dữ liệu trình duyệt",
               "cookie": "cookie phiên đăng nhập", "wallet": "ví tiền điện tử", "cryptocurrenc": "ví/khóa tiền điện tử",
               "screenshot": "chụp màn hình", "keylog": "ghi phím", "clipboard": "nội dung clipboard", "ftp": "tài khoản FTP",
               "telegram": "phiên Telegram", "discord": "token Discord", "steam": "tài khoản Steam", "personal data": "dữ liệu cá nhân",
               "outlook": "hộp thư Outlook", "vpn": "cấu hình VPN"}
STEALER_FAMILIES = ("redline", "lumma", "vidar", "raccoon", "agenttesla", "formbook", "stealc", "risepro", "azorult")
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _ext(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower() if "." in PureWindowsPath(name).name else ""


def _folder(path: str) -> str:
    parts = PureWindowsPath(path).parts
    # C:\Users\<user>\Desktop\... -> Desktop; other paths keep their first two folders.
    if len(parts) > 3 and parts[1].lower() == "users":
        return parts[3]
    return str(PureWindowsPath(*parts[:3])) if parts else path


def decode_powershell(command: str) -> str:
    """Show what an -EncodedCommand actually runs (UTF-16LE base64), bounded and best-effort."""
    match = re.search(r"-e(?:nc(?:odedcommand)?)?\s+[\"']?([A-Za-z0-9+/=]{16,})", command, re.IGNORECASE)
    if not match:
        return ""
    try:
        text = base64.b64decode(match.group(1) + "=" * (-len(match.group(1)) % 4)).decode("utf-16-le", errors="replace")
    except (ValueError, UnicodeDecodeError):
        return ""
    return re.sub(r"<#[^#]*#>", "", text).strip()[:400]


class _Index:
    def __init__(self, bundle):
        self.rows = [e for e in bundle["evidence"]]
        self.by_value, self.by_pid = {}, {}
        for e in self.rows:
            self.by_value.setdefault((e["type"], e["value"].lower()), []).append(e["id"])
            if e["type"] == "process" and e["context"].get("pid") is not None:
                self.by_pid.setdefault(str(e["context"]["pid"]), e["id"])

    def ids(self, kind, value):
        return self.by_value.get((kind, str(value).lower()), [])[:1]

    def process(self, row):
        """The evidence row of this exact process (by PID), not just any process with the same name."""
        found = self.by_pid.get(str(row.get("pid")))
        return [found] if found else self.ids("process", row.get("name"))


def _category(cid, title, severity, facts, evidence_ids, impact, response, tactic=""):
    return {"id": cid, "title": title, "severity": severity, "facts": facts, "evidence_ids": list(dict.fromkeys(evidence_ids))[:20],
            "impact": impact, "response_hint": response, "tactic": tactic}


def analyze_impact(report: dict, bundle: dict, network_profiles: dict | None = None) -> dict:
    content = report["data"]["content"]
    index = _Index(bundle)
    dropped = [d for d in content.get("dropped") or [] if isinstance(d, dict)]
    processes = [p for p in content.get("processes") or [] if isinstance(p, dict)]
    behaviors = [b for b in content.get("behaviors") or [] if isinstance(b, dict)]
    registry = [r for r in content.get("registry") or [] if isinstance(r, dict)]
    configs = [str(c) for c in content.get("malwareConfig") or []]
    tags = {str(t).lower() for t in report["data"].get("analysis", {}).get("tags", [])} | \
           {str(t.get("tag", "")).lower() for t in content.get("threatClasses") or [] if isinstance(t, dict)}
    behavior_ids = {b["name"]: index.ids("behavior", b["name"]) for b in behaviors if b.get("name")}
    categories = []

    # ── Data encryption: x.<user ext>.<marker> on many files means files were encrypted in place.
    double = [(d, _ext(d["filename"]), _ext(d["filename"][: -len(_ext(d["filename"])) - 1])) for d in dropped if _ext(d["filename"])]
    markers = Counter(outer for _, outer, inner in double if inner in USER_DATA_EXT and outer not in USER_DATA_EXT | EXECUTABLE_EXT)
    enc_ext = {m for m, n in markers.items() if n >= 5 and m not in TEMP_EXT}
    encrypted = [d for d, outer, inner in double if outer in enc_ext and inner in USER_DATA_EXT]
    notes = [d for d in dropped if RANSOM_NOTE.search(PureWindowsPath(d["filename"]).name)]
    if encrypted or (notes and "ransomware" in tags):
        originals = Counter(_ext(d["filename"][: -len(_ext(d["filename"])) - 1]) for d in encrypted)
        folders = Counter(_folder(d["filename"]) for d in encrypted)
        facts = [f"{len(encrypted)} tệp người dùng bị mã hóa và đổi đuôi thành " + ", ".join(f".{m.upper()} ({markers[m]})" for m in sorted(enc_ext))]
        if originals:
            facts.append("Loại tệp gốc: " + ", ".join(f".{e} ({n})" for e, n in originals.most_common(8)))
        if folders:
            facts.append("Thư mục bị ảnh hưởng: " + ", ".join(f"{f} ({n})" for f, n in folders.most_common(6)))
        if notes:
            facts.append(f"{len(notes)} ghi chú tiền chuộc, ví dụ " + ", ".join(sorted({PureWindowsPath(n['filename']).name for n in notes})[:3])
                         + " tại " + ", ".join(sorted({_folder(n['filename']) for n in notes})[:4]))
        writers = Counter(d.get("process") or "?" for d in encrypted)
        if writers:
            facts.append("Tiến trình ghi tệp mã hóa: " + ", ".join(f"{p} ({n})" for p, n in writers.most_common(3)))
        facts.append("Ví dụ: " + "; ".join(d["filename"] for d in encrypted[:3]))
        ids = [i for d in encrypted[:10] + notes[:5] for i in index.ids("file", d["filename"])]
        categories.append(_category(
            "data_encryption", "Mã hóa dữ liệu (ransomware)", "critical", facts, ids,
            "Tệp tài liệu, ảnh và dữ liệu người dùng không còn đọc được nếu không có khóa giải mã; máy nhiễm thật có thể mất dữ liệu cục bộ và trên ổ mạng được ánh xạ.",
            "Cô lập máy ngay, không tắt nguồn trước khi thu thập bộ nhớ; khôi phục từ bản sao lưu ngoại tuyến đã kiểm tra; kiểm tra ổ mạng/thư mục chia sẻ có tệp cùng đuôi.",
            "impact"))

    # ── Recovery inhibition: shadow copies, backups and boot recovery.
    recovery, rec_ids = [], []
    for p in processes:
        for pattern, label in RECOVERY_PATTERNS:
            if pattern.search(p.get("cmd", "")):
                recovery.append(f"{label}: {p.get('name')} (PID {p.get('pid')}) `{p.get('cmd', '')[:160]}`")
                rec_ids += index.process(p)
    for b in behaviors:
        if re.search(r"shadow|backup|recovery", b.get("name", ""), re.I):
            recovery.append(f"Chữ ký hành vi: {b['name']}")
            rec_ids += behavior_ids.get(b["name"], [])
    if recovery:
        categories.append(_category("recovery_inhibition", "Ngăn khôi phục hệ thống", "high", recovery[:8], rec_ids,
                                    "Không thể khôi phục tệp từ shadow copy/System Restore trên máy nhiễm.",
                                    "Dùng bản sao lưu nằm ngoài máy (offline/immutable); không dựa vào shadow copy cục bộ.", "impact"))
    elif any(c["id"] == "data_encryption" for c in categories):
        categories[-1]["facts"].append("Không ghi nhận lệnh xóa shadow copy/backup trong sandbox; vẫn cần kiểm tra trên máy thật.")

    # ── Credential and data theft.
    stolen, steal_ids = [], []
    for b in behaviors:
        name = b.get("name", "")
        found = [label for term, label in STEAL_TERMS.items() if re.search(r"\b" + term, name, re.IGNORECASE)]
        if found:
            stolen.append(f"{name} → {', '.join(sorted(set(found)))} ({', '.join(x['name'] for x in b.get('processes', [])[:2])})")
            steal_ids += behavior_ids.get(name, [])
    family = next((f for f in STEALER_FAMILIES if f in tags or any(f in c.lower() for c in configs)), "")
    for c in configs:
        if family and family in c.lower():
            botnet = re.search(r'"Botnet":\s*"([^"]+)"', c)
            stolen.append(f"Cấu hình {family.title()} trích xuất được" + (f", botnet \"{botnet.group(1)}\"" if botnet else ""))
            steal_ids += index.ids("malware_config", c)
    if stolen or family:
        categories.append(_category(
            "credential_theft", "Đánh cắp thông tin đăng nhập/dữ liệu", "high",
            (stolen or [f"Họ mã độc {family.title()} là infostealer"])[:8], steal_ids,
            "Mật khẩu đã lưu trong trình duyệt, cookie phiên, ví tiền điện tử và token ứng dụng trên máy nhiễm có thể đã bị gửi ra ngoài; "
            "kẻ tấn công có thể đăng nhập bằng phiên bị đánh cắp mà không cần mật khẩu.",
            "Từ máy sạch: đổi mật khẩu tài khoản đã đăng nhập trên máy, thu hồi phiên/token, kiểm tra MFA và đăng nhập bất thường.",
            "credential-access"))

    # ── Persistence: scheduled tasks, Run keys, startup folder, services.
    persist, per_ids = [], []
    for p in processes:
        cmd = p.get("cmd", "")
        if re.search(r"schtasks(\.exe)?\"?\s+/create", cmd, re.I):
            name = re.search(r"/TN\s+\"?([^\"/]+?)\"?\s+/", cmd, re.I)
            target = re.search(r"/TR\s+\"?([^\"]+?)\"?\s+/", cmd, re.I) or re.search(r"/TR\s+\"?([^\"]+)", cmd, re.I)
            when = re.search(r"/SC\s+(\w+)", cmd, re.I)
            persist.append(f"Scheduled task \"{name.group(1).strip() if name else '?'}\" chạy {target.group(1).strip() if target else '?'}"
                           + (f" khi {when.group(1).upper()}" if when else "") + (" với quyền cao nhất" if "/rl highest" in cmd.lower() else ""))
            per_ids += index.process(p)
        if re.search(r"\bsc(\.exe)?\s+create\b|new-service", cmd, re.I):
            persist.append(f"Tạo dịch vụ: `{cmd[:160]}`")
            per_ids += index.process(p)
    for r in registry:
        if re.search(r"\\currentversion\\run|\\winlogon|\\services\\", r.get("key", ""), re.I) and r.get("operation", "").lower() not in {"read", "delete"}:
            persist.append(f"Registry {r.get('key')}\\{r.get('name', '')} = {r.get('value', '')[:120]}")
            per_ids += index.ids("registry", r.get("key"))
    startup = [d for d in dropped if "\\start menu\\programs\\startup\\" in d["filename"].lower() and _ext(d["filename"]) in EXECUTABLE_EXT | {"wnry"}]
    if startup:
        persist.append(f"{len(startup)} tệp đặt trong thư mục Startup, ví dụ " + ", ".join(PureWindowsPath(d["filename"]).name for d in startup[:4]))
        per_ids += [i for d in startup[:5] for i in index.ids("file", d["filename"])]
    for b in behaviors:
        if re.search(r"autorun|startup directory|task scheduler|scheduled task|windows services", b.get("name", ""), re.I):
            per_ids += behavior_ids.get(b["name"], [])
    if persist:
        categories.append(_category("persistence", "Cơ chế tự khởi động", "high", persist[:10], per_ids,
                                    "Mã độc tự chạy lại sau khi đăng nhập/khởi động lại; xóa tệp chính mà bỏ sót các cơ chế này sẽ bị tái nhiễm.",
                                    "Xuất cấu hình rồi gỡ đúng từng task/registry value/tệp Startup đã liệt kê; kiểm tra lại sau một lần đăng nhập.",
                                    "persistence"))

    # ── Defence impairment: Defender exclusions, policy bypass, ACL and attribute changes.
    evasion, ev_ids = [], []
    for p in processes:
        cmd = p.get("cmd", "")
        decoded = decode_powershell(cmd)
        text = cmd + " " + decoded
        for path in re.findall(r"-ExclusionPath\s+['\"]?([^'\"]+)", text, re.I):
            path = re.split(r"\s+-\w", path)[0].strip()
            scope = " (toàn bộ hồ sơ người dùng và ổ hệ thống bị loại khỏi quét)" if re.search(r"\$env:(userprofile|systemdrive)", path, re.I) else ""
            evasion.append(f"Thêm vào danh sách loại trừ Defender: {path[:140]}{scope}")
            ev_ids += index.process(p)
        if re.search(r"set-mppreference.*-disable", text, re.I):
            evasion.append(f"Tắt tính năng Defender: `{text[:160]}`")
        if re.search(r"icacls.*/grant\s+everyone:f", cmd, re.I):
            evasion.append(f"Cấp toàn quyền cho Everyone: `{cmd[:120]}`")
            ev_ids += index.process(p)
        if re.search(r"\battrib(\.exe)?\s+\+h", cmd, re.I):
            evasion.append(f"Ẩn tệp/thư mục: `{cmd[:120]}`")
    for b in behaviors:
        if re.search(r"defender|execution policy|disable|uac|takes ownership", b.get("name", ""), re.I):
            ev_ids += behavior_ids.get(b["name"], [])
    if evasion:
        uniq = list(dict.fromkeys(evasion))
        categories.append(_category("defense_impairment", "Vô hiệu hóa/né tránh phòng thủ", "high", uniq[:10], ev_ids,
                                    "Các thư mục bị loại trừ sẽ không bị Defender quét; mã độc nằm ở đó có thể tồn tại dù đã quét toàn máy.",
                                    "Xóa các exclusion đã liệt kê, bật lại tính năng Defender, rồi quét lại; kiểm tra chính sách GPO/Intune có ghi đè không.",
                                    "defense-impairment"))

    # ── Execution: encoded PowerShell and script hosts, shown decoded where possible.
    execution, ex_ids = [], []
    for p in processes:
        cmd, name = p.get("cmd", ""), str(p.get("name", "")).lower()
        decoded = decode_powershell(cmd)
        if decoded:
            execution.append(f"PowerShell mã hóa base64 ({p.get('name')} PID {p.get('pid')}) thực chất chạy: {decoded}")
            ex_ids += index.process(p)
        elif name in {"cscript.exe", "wscript.exe", "mshta.exe"} and cmd:
            execution.append(f"Script host: `{cmd[:140]}`")
            ex_ids += index.process(p)
    if execution:
        categories.append(_category("execution", "Thực thi lệnh/script", "medium", list(dict.fromkeys(execution))[:8], ex_ids,
                                    "Mã độc dùng công cụ có sẵn của Windows để chạy lệnh, khó bị chặn bằng danh sách ứng dụng đơn giản.",
                                    "Tìm cùng command line trong log EDR/PowerShell (Event ID 4104) trên các máy khác.", "execution"))

    # ── Dropped executables: what a responder has to find and remove.
    # PowerShell writes __PSScriptPolicyTest_* itself; it is not a dropped payload.
    exes = [d for d in dropped if (_ext(d["filename"]) in EXECUTABLE_EXT or d.get("type") == "executable")
            and not PureWindowsPath(d["filename"]).name.startswith("__PSScriptPolicyTest_")]
    if exes:
        by_proc = Counter(d.get("process") or "?" for d in exes)
        facts = [f"{len(exes)} tệp thực thi/script được tạo, nhiều nhất bởi " + ", ".join(f"{p} ({n})" for p, n in by_proc.most_common(3))]
        facts += [f"{d['filename']} (SHA256 {str((d.get('hashes') or {}).get('sha256', ''))[:16]}…)" for d in exes[:6]]
        categories.append(_category("payload_drop", "Thả tệp thực thi", "medium", facts,
                                    [i for d in exes[:10] for i in index.ids("file", d["filename"])],
                                    "Các tệp này là thành phần cần tìm và loại bỏ trên máy thật; chúng có thể được chạy lại qua cơ chế tự khởi động.",
                                    "Tìm theo SHA256 trong EDR toàn tổ chức; quarantine thay vì xóa để giữ bằng chứng.", "execution"))

    # ── Network-side impact reuses the destination profiles.
    profiles = list((network_profiles or {}).values())
    c2 = [p for p in profiles if p["role"] in {"config_c2", "known_c2", "malicious_reported", "malware_distribution", "payload_download"}]
    if c2:
        categories.append(_category("c2_communication", "Liên lạc với hạ tầng tấn công", max((p["severity"] for p in c2), key=lambda s: SEVERITY_RANK.get(s, 0)),
                                    [f"{p['value']}: {p['meaning']}" for p in c2[:6]], [i for p in c2 for i in p["evidence_ids"][:2]],
                                    "Máy nhiễm có thể nhận lệnh, tải thêm mã độc hoặc gửi dữ liệu ra ngoài.",
                                    "Chặn đúng các đích này sau khi xác minh trong log; tìm máy khác đã kết nối tới chúng.", "command-and-control"))
    spread = [p for p in profiles if p["role"] == "smb_propagation"]
    if spread:
        categories.append(_category("lateral_spread", "Lây lan trong mạng nội bộ", "critical",
                                    [f"Kết nối SMB tới {spread[0]['smb_scan_peers']} địa chỉ khác nhau, ví dụ " + ", ".join(p["value"] for p in spread[:5])],
                                    [i for p in spread[:10] for i in p["evidence_ids"][:1]],
                                    "Các máy Windows chưa vá lỗ hổng SMB trong cùng mạng có thể bị nhiễm tiếp.",
                                    "Chặn 445/139 giữa các phân đoạn mạng, vá MS17-010 và rà soát máy đã nhận kết nối SMB.", "lateral-movement"))

    categories.sort(key=lambda c: -SEVERITY_RANK.get(c["severity"], 0))
    worst = categories[0]["severity"] if categories else "info"
    summary = ("; ".join(f"{c['title']}: {c['facts'][0]}" for c in categories[:4]) if categories
               else "Không rút ra được tác động cụ thể từ dữ liệu sandbox; cần thêm log từ máy thật.")
    return {"severity": worst, "summary": summary, "categories": categories,
            "limitations": ["Dữ liệu là quan sát trong sandbox với tệp mồi; số lượng tệp trên máy thật có thể khác.",
                            "Không ghi nhận trong sandbox không có nghĩa là không xảy ra trên máy thật."]}
