"""Code-level evidence: the disassembly around each API call that implements a behaviour.

Ghidra reads the sample without running it, so a listing proves the code is present in the
file, not that it executed. Each behaviour is therefore reported next to the impact category
the sandbox observed, and says so when the sandbox observed nothing matching.
"""
from __future__ import annotations

from datetime import datetime, timezone

# Behaviour id -> title, ATT&CK tactic and the imported API base names that implement it.
# Ids shared with impact_analysis categories let the two be shown side by side. Base names
# cover the A/W/Ex variants (RegSetValue matches RegSetValueExA).
BEHAVIOR_APIS = {
    "data_encryption": {
        "title": "Mã hóa dữ liệu", "tactic": "Impact",
        "apis": ["CryptAcquireContext", "CryptGenKey", "CryptImportKey", "CryptDeriveKey", "CryptEncrypt",
                 "BCryptEncrypt"]},
    "credential_theft": {
        "title": "Thu thập thông tin/dữ liệu", "tactic": "Credential Access / Collection",
        "apis": ["CryptUnprotectData", "GetAsyncKeyState", "SetWindowsHookEx", "GetClipboardData", "BitBlt"]},
    "persistence": {
        "title": "Cơ chế tự khởi động", "tactic": "Persistence",
        "apis": ["RegSetValue", "RegCreateKey", "CreateService", "StartService"]},
    "defense_impairment": {
        "title": "Né tránh phòng thủ / tiêm tiến trình", "tactic": "Defense Evasion",
        "apis": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "CreateRemoteThread", "WriteProcessMemory",
                 "VirtualAllocEx", "NtUnmapViewOfSection"]},
    "execution": {
        "title": "Thực thi lệnh/tiến trình", "tactic": "Execution",
        "apis": ["CreateProcess", "WinExec", "ShellExecute"]},
    "payload_drop": {
        "title": "Thả hoặc tải tệp", "tactic": "Execution / Ingress Tool Transfer",
        "apis": ["FindResource", "LoadResource", "URLDownloadToFile", "WriteFile"]},
    "c2_communication": {
        "title": "Liên lạc mạng", "tactic": "Command and Control",
        "apis": ["InternetOpen", "InternetOpenUrl", "InternetConnect", "HttpSendRequest", "WinHttpConnect",
                 "WSAStartup", "socket", "connect", "send", "recv", "gethostbyname"]},
    "lateral_spread": {
        "title": "Dò quét/lây lan trong mạng", "tactic": "Discovery / Lateral Movement",
        "apis": ["GetAdaptersInfo", "NetShareEnum", "WNetAddConnection2"]},
    "dynamic_loading": {
        "title": "Nạp mã động / giải nén lúc chạy", "tactic": "Defense Evasion",
        "apis": ["LoadLibrary", "GetProcAddress", "VirtualAlloc", "VirtualProtect"]},
}
API_SUFFIXES = ("", "A", "W", "Ex", "ExA", "ExW")
TRACKED_APIS = [api for spec in BEHAVIOR_APIS.values() for api in spec["apis"]]
REPORT_SITES_PER_BEHAVIOR = 3
STATIC_NOTE = ("Đoạn mã chứng minh mẫu có lệnh gọi API này. Ghidra không chạy tệp, nên việc lệnh đã thực thi "
               "hay chưa do dữ liệu sandbox xác nhận.")
PACKED_NOTE = ("Không tìm thấy lệnh gọi API theo dõi nào. Mẫu có thể bị pack, là .NET (cần ILSpy/dnSpy) "
               "hoặc gọi API qua địa chỉ tính lúc chạy.")


def _base_api(name: str) -> str:
    return next((api for api in TRACKED_APIS for suffix in API_SUFFIXES if name == api + suffix), "")


def format_listing(site: dict) -> str:
    """One call site as a fixed-width listing; the tracked CALL is marked with '>>'."""
    lines = []
    for row in site.get("instructions") or []:
        raw = str(row.get("bytes") or "").split()
        shown = " ".join(raw[:8]) + (" .." if len(raw) > 8 else "")
        line = f'{">>" if row.get("is_call") else "  "} {row.get("address", "")}  {shown:<26} {row.get("text", "")}'
        comment = str(row.get("comment") or "")
        lines.append(f"{line:<78} ; {comment}" if comment else line)
    return "\n".join(lines)


def build_code_evidence(summary: dict) -> dict:
    """Group the call sites Ghidra exported by the behaviour their API implements."""
    sites = [s for s in summary.get("call_sites") or [] if isinstance(s, dict)]
    counts = {name: n for name, n in (summary.get("call_counts") or {}).items() if isinstance(n, int)}
    behaviors = []
    for behavior_id, spec in BEHAVIOR_APIS.items():
        apis = [{"name": name, "call_count": n} for name, n in sorted(counts.items())
                if _base_api(name) in spec["apis"]]
        rows = [{**site, "listing": format_listing(site)} for site in sites if site.get("base_api") in spec["apis"]]
        if apis or rows:
            behaviors.append({"id": behavior_id, "title": spec["title"], "tactic": spec["tactic"],
                              "apis": apis, "call_sites": rows})
    return {"behaviors": behaviors, "total_call_sites": sum(len(b["call_sites"]) for b in behaviors),
            "total_calls": sum(counts.values()), "note": STATIC_NOTE if behaviors else PACKED_NOTE}


def static_record(analysis: dict, case: dict) -> dict:
    """What is stored with a case: sample identity, tool version and the code evidence."""
    triage = analysis.get("triage") or {}
    summary = (analysis.get("ghidra") or {}).get("summary") or {}
    known = {str(row.get("value", "")).lower() for row in (case.get("evidence_bundle") or {}).get("evidence", [])
             if row.get("type") in {"md5", "sha1", "sha256"}}
    hashes = {triage.get(kind, "") for kind in ("md5", "sha1", "sha256")} - {""}
    return {
        "filename": triage.get("filename", ""), "sha256": triage.get("sha256", ""), "md5": triage.get("md5", ""),
        "size": triage.get("size", 0), "hash_match": bool(hashes & known),
        "analyzed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tool": "Ghidra " + str(summary.get("ghidra_version") or ""), "language": summary.get("language", ""),
        "executable_format": summary.get("executable_format", ""),
        "code_evidence": analysis.get("code_evidence") or build_code_evidence(summary),
    }


def report_blocks(payload: dict) -> dict | None:
    """Plain-text structure shared by the Markdown/HTML/PDF exporters; callers escape their format."""
    static = payload.get("static_analysis") or {}
    evidence = static.get("code_evidence") or {}
    if not evidence.get("behaviors"):
        return None
    observed = {c["id"]: c["title"] for c in (payload.get("impact_analysis") or {}).get("categories", [])}
    intro = [f'Mẫu: {static.get("filename")}; SHA256 {static.get("sha256")}; {static.get("executable_format")} '
             f'{static.get("language")}; {static.get("tool", "").strip()}; {static.get("analyzed_at")}',
             "Hash của mẫu có trong hồ sơ sandbox này." if static.get("hash_match") else
             "CẢNH BÁO: hash của mẫu không có trong hồ sơ sandbox này; chưa chứng minh đây là cùng một tệp.",
             evidence.get("note", STATIC_NOTE)]
    behaviors = []
    for b in evidence["behaviors"]:
        status = (f'Khớp nhóm tác động sandbox đã quan sát: {observed[b["id"]]}.' if b["id"] in observed else
                  "Sandbox không ghi nhận nhóm tác động tương ứng; đây là năng lực có trong mã, "
                  "chưa phải hành vi đã xảy ra.")
        apis = ", ".join(f'{a["name"]} ({a["call_count"]} lệnh gọi)' for a in b["apis"])
        sites = [{"caption": f'{s.get("library") or "?"}::{s.get("api")} gọi tại {s.get("address")} '
                             f'trong hàm {s.get("function") or "(không thuộc hàm nào)"}',
                  "listing": s.get("listing") or format_listing(s)}
                 for s in b["call_sites"][:REPORT_SITES_PER_BEHAVIOR]]
        behaviors.append({"title": f'{b["title"]} ({b["tactic"]})', "status": status, "apis": apis, "sites": sites,
                          "omitted": max(0, len(b["call_sites"]) - len(sites))})
    return {"heading": "Bằng chứng mức mã lệnh (phân tích tĩnh Ghidra)", "intro": intro, "behaviors": behaviors}


def code_evidence_markdown(payload: dict) -> str:
    blocks = report_blocks(payload)
    if not blocks:
        return ""

    # A string literal lifted from the sample must not be able to close the code fence.
    def fence(text):
        return "```asm\n" + text.replace("`", "'") + "\n```"

    def plain(text):
        return str(text).replace("`", "'").replace("<", "&lt;").replace("|", "&#124;")

    lines = ["", "### " + blocks["heading"], ""] + ["- " + plain(x) for x in blocks["intro"]]
    for b in blocks["behaviors"]:
        lines += ["", "#### " + plain(b["title"]), "", plain(b["status"]), "", "API: " + plain(b["apis"])]
        for site in b["sites"]:
            lines += ["", plain(site["caption"]), "", fence(site["listing"])]
        if b["omitted"]:
            lines += ["", f'Còn {b["omitted"]} vị trí gọi khác trong bản JSON.']
    return "\n".join(lines) + "\n"
