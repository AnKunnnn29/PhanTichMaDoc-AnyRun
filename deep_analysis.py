"""Evidence-linked process stories, static clues and family comparisons (no execution)."""
from __future__ import annotations

import base64
import ipaddress
import json
import ntpath
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from impact_analysis import encryption_markers
from mitre_mapping import catalogue

EXEC = {".exe", ".dll", ".scr", ".sys", ".msi", ".com"}
SCRIPT = {".ps1", ".vbs", ".js", ".bat", ".cmd", ".hta", ".wsf"}
LOL_RULES = [
    ("certutil.exe", r"-(?:urlcache|verifyctl)\b", "T1105", "Tải tệp bằng certutil"),
    ("certutil.exe", r"-decode(?:hex)?\b", "T1140", "Giải mã tệp bằng certutil"),
    ("bitsadmin.exe", r"/(?:transfer|addfile)\b", "T1197", "Tạo tác vụ tải bằng BITS"),
    ("mshta.exe", r"(?:https?://|javascript:|vbscript:|\.hta\b)", "T1218.005", "Thực thi nội dung qua mshta"),
    ("rundll32.exe", r"(?:\.dll[\"']?\s*,|javascript:)", "T1218.011", "Thực thi hàm DLL qua rundll32"),
    ("regsvr32.exe", r"(?:/i:|scrobj\.dll|https?://)", "T1218.010", "Đăng ký/thực thi nội dung qua regsvr32"),
    ("wmic.exe", r"process\s+call\s+create", "T1047", "Tạo tiến trình qua WMI"),
    ("cscript.exe", r"\.(?:vbs|js|wsf)\b", "T1059.005", "Chạy script bằng Windows Script Host"),
    ("powershell.exe", r"(?:-enc\w*\b|invoke-expression|downloadstring|add-mppreference|set-mppreference)", "T1059.001", "PowerShell có nội dung cần kiểm tra"),
    ("schtasks.exe", r"/create\b", "T1053.005", "Tạo scheduled task"),
]


def path_key(value):
    """Windows lexical comparison only; never expand the analysis host's environment."""
    value = str(value or "").strip().strip('"').replace("/", "\\")
    for prefix in ("\\??\\", "\\\\?\\"):
        if value.startswith(prefix):
            value = value[len(prefix):]
    return ntpath.normpath(value).casefold() if value else ""


# Used only when no case-wide detection is available (single-file calls); the pipeline passes detected markers.
KNOWN_ENCRYPTION_MARKERS = {"wncry"}


def classify_file(path, kind="", markers=None):
    name = ntpath.basename(path_key(path))
    extension = ntpath.splitext(name)[1]
    if extension.lstrip(".") in (KNOWN_ENCRYPTION_MARKERS if markers is None else markers):
        return "encrypted_file"
    if re.search(r"(?:read_?me|decrypt|ransom|how_to|@please)", name) and extension in {".txt", ".html", ".hta", ".bmp", ".png"}:
        return "ransom_note"
    if extension in SCRIPT:
        return "script"
    if extension in EXEC or kind == "executable":
        return "executable_candidate"
    if extension == ".wnry":
        return "language_resource" if re.search(r"(?:^|\\)msg\\m_", path_key(path)) else "family_resource_candidate"
    if extension in {".tmp", ".temp", ".wncryt"}:
        return "temporary"
    return "other"


def analyze_command(command, executable=""):
    original = str(command or "")[:16000]
    normalized = re.sub(r"\^(.)", r"\1", original)
    # Fold literal concatenation only. No interpreter, eval, shell or host-variable expansion.
    literal = re.compile(r"(['\"])([^'\"\r\n]{0,1000})\1\s*\+\s*(['\"])([^'\"\r\n]{0,1000})\3")
    for _ in range(16):
        folded = literal.sub(lambda m: '"' + m[2] + m[4] + '"', normalized)
        if folded == normalized:
            break
        normalized = folded
    decoded = ""
    enc = re.search(r"-(?:e|enc|encodedcommand)\s+[\"']?([A-Za-z0-9+/=]{16,12000})", normalized, re.I)
    if enc and ntpath.basename(str(executable)).lower() in {"powershell.exe", "pwsh.exe"}:
        try:
            decoded = base64.b64decode(enc[1], validate=True).decode("utf-16-le")[:6000]
        except (ValueError, UnicodeDecodeError):
            pass
    text = normalized + "\n" + decoded
    for _ in range(16):
        folded = literal.sub(lambda m: '"' + m[2] + m[4] + '"', text)
        if folded == text:
            break
        text = folded
    urls = list(dict.fromkeys(re.findall(r"https?://[^\s'\"<>)+]+", text, re.I)))[:30]
    ips = []
    for candidate in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        try:
            ip = str(ipaddress.ip_address(candidate))
            if ip not in ips:
                ips.append(ip)
        except ValueError:
            pass
    paths = list(dict.fromkeys(m.group(1) or m.group(2) for m in re.finditer(
        r'"([A-Za-z]:\\[^"\r\n]+)"|([A-Za-z]:\\[^\s"\r\n;]+)', text)))[:30]
    image = ntpath.basename(str(executable)).lower()
    findings = [{"technique_id": tid, "summary": label, "assessment_status": "inference", "confidence": "medium"}
                for name, pattern, tid, label in LOL_RULES if name == image and re.search(pattern, text, re.I)]
    # Script Host's .js is JavaScript, not Visual Basic; flag-only invocations prove nothing.
    for finding in findings:
        if image == "cscript.exe" and re.search(r"\.js\b", text, re.I):
            finding["technique_id"] = "T1059.007"
    return {"original": original, "normalized": normalized, "decoded_powershell": decoded,
            "urls": urls, "ips": ips[:30], "paths": paths,
            "environment_variables": sorted(set(re.findall(r"%[A-Za-z_][A-Za-z0-9_]*%|\$env:[A-Za-z_][A-Za-z0-9_]*", text, re.I))),
            "environment_expansion": "not_resolved_without_sandbox_environment", "findings": findings,
            "limitations": ["Gỡ rối một phần bằng quy tắc; không thực thi và không giải được mọi biểu thức."]}


def _fact(summary, ids, status="observed", confidence="high", **extra):
    return {"summary": summary, "evidence_ids": list(dict.fromkeys(ids)),
            "assessment_status": status, "confidence": confidence, **extra}


def build_process_story(bundle):
    rows = bundle["evidence"]
    procs = [e for e in rows if e["type"] == "process"]
    pid_count = Counter(str(e["context"].get("pid")) for e in procs)
    uuid_count = Counter(e["context"].get("uuid") for e in procs if e["context"].get("uuid"))
    by_pid = {str(e["context"]["pid"]): e for e in procs if e["context"].get("pid") and pid_count[str(e["context"]["pid"])] == 1}
    by_uuid = {e["context"]["uuid"]: e for e in procs if e["context"].get("uuid") and uuid_count[e["context"]["uuid"]] == 1}
    relations = {e["context"].get("childUuid"): e for e in rows if e["type"] == "process_relation"}
    stories, children = [], defaultdict(list)
    markers = encryption_markers(e["value"] for e in rows if e["type"] == "file") | KNOWN_ENCRYPTION_MARKERS
    for p in procs:
        c = p["context"]
        parent = by_uuid.get(c.get("parentUuid")) if c.get("ppidBasis") == "graph_uuid" else by_pid.get(str(c.get("ppid")))
        if parent and parent["id"] != p["id"]:
            children[parent["id"]].append(p["id"])
    for p in procs:
        c = p["context"]
        uid, pid = c.get("uuid"), c.get("pid")
        artifacts = []
        for e in rows:
            if e["id"] == p["id"] or e["type"] in {"process", "process_relation", "pe_metadata", "file_type"}:
                continue
            ctx = e["context"]
            # Name-only association is deliberately excluded, including repeated PIDs.
            same = (bool(uid) and ctx.get("processUuid") == uid and uuid_count[uid] == 1)
            same = same or (pid_count[str(pid)] == 1 and bool(pid) and str(ctx.get("pid")) == str(pid))
            if not same and e["type"] == "behavior":
                same = pid_count[str(pid)] == 1 and any(str(v.get("pid")) == str(pid) for v in ctx.get("processes", []))
            if same:
                artifacts.append(e)
        parent = by_uuid.get(c.get("parentUuid")) if c.get("ppidBasis") == "graph_uuid" else by_pid.get(str(c.get("ppid")))
        parent_ids = [p["id"], parent["id"]] if parent else []
        rel = relations.get(uid)
        if rel and parent:
            parent_ids.append(rel["id"])
        command = analyze_command(c.get("cmd") or c.get("commandLine"), p["value"])
        for f in command["findings"]:
            f["evidence_ids"] = [p["id"]]
        flags = []
        key = path_key(c.get("path"))
        name = ntpath.basename(key) or p["value"].lower()
        if name == "exploer.exe" or (name in {"svchost.exe", "lsass.exe", "services.exe", "winlogon.exe"}
                                      and key and not re.match(r"^[a-z]:\\windows\\(?:system32|syswow64)\\", key)):
            flags.append(_fact("Tên/vị trí giống thành phần hệ thống cần kiểm tra", [p["id"]], "inference", "medium", technique_id="T1036"))
        if name == "system.exe" and "\\startup\\" in key:
            flags.append(_fact("System.exe trong Startup cần xác minh ngụy trang và tự khởi động", [p["id"]], "inference", "medium", technique_id="T1036"))
        if re.search(r"[^\x00-\x7f]", name):
            flags.append(_fact("Tên tệp có ký tự ngoài ASCII; riêng dấu hiệu này không chứng minh ngụy trang", [p["id"]], "inference", "low"))
        roles = []
        dropped = [e for e in artifacts if e["type"] == "file" and "/dropped/" in e["source_path"]]
        executables = [e for e in dropped if classify_file(e["value"], e["context"].get("type"), markers) == "executable_candidate"]
        if executables:
            roles.append(_fact("Ứng viên dropper: tạo tệp thực thi", [p["id"]] + [e["id"] for e in executables[:3]], "inference", "medium", role="dropper_candidate"))
        if command["findings"]:
            roles.append(_fact("Công cụ hệ thống có cách gọi cần kiểm tra", [p["id"]], "inference", "medium", role="system_tool_candidate"))
        if any(f["technique_id"] in {"T1218.005", "T1218.010", "T1218.011"} for f in command["findings"]):
            roles.append(_fact("Ứng viên loader: lệnh dùng host để nạp DLL/nội dung", [p["id"]], "inference", "medium", role="loader_candidate"))
        startup = [e for e in artifacts if e["type"] == "registry" and "\\currentversion\\run" in e["value"].lower()
                   and str(e["context"].get("operation", "")).lower() in {"write", "setvalue", "regsetvalue", "create"}]
        if startup or any(f["technique_id"] == "T1053.005" for f in command["findings"]):
            roles.append(_fact("Ứng viên tự khởi động: cần kiểm tra cấu hình đã tạo", [p["id"]] + [e["id"] for e in startup],
                               "inference", "medium", role="persistence_candidate"))
        if c.get("isInjected") is True:
            roles.append(_fact("Nguồn gắn cờ tiến trình bị inject", [p["id"]], "signature", "medium", role="injected_reported"))
        story = {"id": p["id"], "uuid": uid, "pid": pid, "name": p["value"], "path": c.get("path", ""),
                 "timestamp": c.get("startTime") or c.get("timestamp"), "time_basis": c.get("timeBasis", "not_available"),
                 "parent": {"id": parent["id"], "name": parent["value"], "basis": c.get("ppidBasis", "source_ppid"),
                            "assessment_status": "inference" if c.get("ppidBasis") == "unique_parent_name" else "observed",
                            "evidence_ids": parent_ids} if parent else None,
                 "children": children[p["id"]], "artifacts": [{"id": e["id"], "type": e["type"], "value": e["value"],
                    "file_category": classify_file(e["value"], e["context"].get("type"), markers) if e["type"] == "file" else None,
                    "assessment_status": "signature" if e["type"] == "behavior" else "observed"} for e in artifacts],
                 "command_analysis": command, "roles": roles, "flags": flags, "evidence_ids": [p["id"]]}
        stories.append(story)
    drop_exec = []
    for e in rows:
        if e["type"] != "file" or "/dropped/" not in e["source_path"]:
            continue
        path = path_key(e["value"])
        if not path or "%" in path or not ntpath.isabs(path):
            continue
        for p in stories:
            if path != path_key(p["path"]):
                continue
            same_pid = str(e["context"].get("pid")) == str(p["pid"])
            parent = p.get("parent")
            ordered_parent = parent and parent["basis"] == "graph_uuid" and pid_count[str(e["context"].get("pid"))] == 1 and any(
                str(v["pid"]) == str(e["context"].get("pid")) and v["id"] == parent["id"] for v in stories)
            written, executed = _date(e["context"].get("timestamp")), _date(p.get("timestamp"))
            delta = (executed - written).total_seconds() if written and executed else None
            chronology = "source_times_compatible" if delta is not None and delta >= 0 else "source_times_conflict" if delta is not None else "not_proven"
            drop_exec.append(_fact("Tệp được thả khớp đường dẫn tiến trình; cần đối chiếu thứ tự ghi và chạy",
                                   [e["id"], p["id"]], "inference", "medium", path=e["value"], process_id=p["id"],
                                   writer_pid=e["context"].get("pid"), same_pid=same_pid,
                                   writer_is_graph_parent=bool(ordered_parent), chronology=chronology,
                                   seconds_between_source_times=delta, near_in_time=delta is not None and 0 <= delta <= 5))
            p["roles"].append(_fact("Ứng viên payload: đường dẫn khớp tệp được thả", [e["id"], p["id"]], "inference", "medium", role="payload_candidate"))
    narrative = []
    for p in sorted(stories, key=lambda r: (not bool(r["timestamp"]), str(r["timestamp"] or ""))):
        parent = p["parent"]
        if parent:
            narrative.append(_fact(f'{parent["name"]} → {p["name"]} (PID {p["pid"]})', parent["evidence_ids"], parent["assessment_status"],
                                   "high" if parent["basis"] == "graph_uuid" else "low", process_id=p["id"]))
        elif len(stories) <= 2:
            narrative.append(_fact(f'Nguồn ghi nhận {p["name"]} (PID {p["pid"]})', [p["id"]], process_id=p["id"]))
    return {"processes": stories, "drop_execute": drop_exec, "narrative": narrative,
            "limitations": ["Cạnh UUID là quan hệ được sandbox báo cáo, không xác nhận endpoint thật bị nhiễm.",
                            "Không gán artifact bằng tên tiến trình; PID trùng cần UUID để phân biệt.",
                            "Khớp tệp với tiến trình không đủ chứng minh thả-rồi-chạy hay thời gian thực thi gần nhau."]}


def _date(value):
    try:
        if str(value).isdigit():
            return datetime.fromtimestamp(int(value) / (1000 if len(str(value)) >= 13 else 1), timezone.utc)
        text = re.sub(r"^(\d{4}):(\d{2}):(\d{2})", r"\1-\2-\3", str(value)).replace("Z", "+00:00")
        d = datetime.fromisoformat(text)
        return d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d.astimezone(timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


def build_static_profile(report, bundle):
    rows = bundle["evidence"]
    static = report["data"]["content"].get("staticProfile") or {}
    analysis_time = _date(static.get("analysisTime"))
    findings, runtime, capabilities = [], [], []
    for e in rows:
        if e["type"] == "pe_metadata" and e["context"].get("name", "").lower() in {"timestamp", "compiletimestamp", "timedatestamp", "linkerdate"}:
            stamp = _date(e["value"])
            if stamp and analysis_time and (stamp - analysis_time).total_seconds() > 86400:
                findings.append(_fact("Timestamp PE sau thời điểm phân tích; cần xác minh toolchain hoặc metadata bị sửa", [e["id"]], "inference", "medium",
                                      kind="future_pe_timestamp", value=e["value"], analysis_time=analysis_time.isoformat(),
                                      not_conclusive_for="timestomping", references=["https://attack.mitre.org/techniques/T1070/006/"]))
        if e["type"] == "behavior" and "untrusted certificate" in e["value"].lower():
            findings.append(_fact("Chữ ký hành vi nguồn báo chạy tệp có chứng thư không tin cậy; chưa tự xác minh Authenticode",
                                  [e["id"]], "signature", "medium", kind="untrusted_certificate_signature",
                                  scope="source_behavior_signature"))
    groups = defaultdict(list)
    for e in rows:
        if e["type"] == "module":
            groups[e["context"].get("processUuid") or str(e["context"].get("pid"))].append(e)
    for key, modules in groups.items():
        names = {ntpath.basename(path_key(e["value"])): e for e in modules}
        managed = [names[n] for n in ("mscoree.dll", "clr.dll", "coreclr.dll") if n in names]
        if managed:
            runtime.append(_fact("Tiến trình nạp thành phần .NET; cân nhắc ILSpy/dnSpy khi kiểm tra managed assembly", [e["id"] for e in managed],
                                 "observed", "high", process=managed[0]["context"].get("process"), process_key=key,
                                 conclusion="runtime_components_observed_not_proof_of_maliciousness", tools=["ILSpy", "dnSpy"],
                                 scope="process_not_necessarily_main_container"))
        for dll, hint in {"vaultcli.dll": "Có thể tương tác Windows Vault", "dpapi.dll": "Có thể tương tác DPAPI",
                          "rstrtmgr.dll": "Có thể dùng Restart Manager", "samlib.dll": "Có thể truy vấn tài khoản SAM"}.items():
            if dll in names:
                e = names[dll]
                capabilities.append(_fact(hint + "; nạp DLL chưa chứng minh lời gọi API hay đánh cắp dữ liệu", [e["id"]],
                                          "inference", "low", process=e["context"].get("process"), dll=dll,
                                          verification="Đối chiếu API trace, command line và hành vi cùng tiến trình."))
    trid = [_fact(e["value"], [e["id"]], "signature", "medium", extension=e["context"].get("extension"))
            for e in rows if e["type"] == "file_type"]
    return {"available": bool(static or runtime), "metadata_scope": "main_object_only", "findings": findings,
            "runtime": runtime, "dll_capabilities": capabilities, "trid": trid,
            "signature": {"status": static.get("signature_status", "not_reported"),
                          "evidence_ids": [e["id"] for e in rows if e["type"] == "pe_metadata" and e["context"].get("name") == "SignatureStatus"],
                          "note": "Chỉ hiển thị trạng thái nguồn báo cáo, chưa xác minh Authenticode. Thiếu dữ liệu không đồng nghĩa không có chữ ký."},
            "limitations": ["TrID là nhận diện xác suất, không phải kết luận tệp độc hại.",
                            "DLL chỉ cung cấp giả thuyết năng lực yếu; không dùng để đổi verdict hoặc tự chặn."]}


@lru_cache(maxsize=1)
def family_catalog():
    return json.loads((Path(__file__).parent / "data/family_expectations.json").read_text(encoding="utf-8"))


def compare_family(threat, mappings):
    catalog = family_catalog()
    label = str(threat.get("threat_name", "")).lower()
    family = next((name for name, row in catalog["families"].items()
                   if label in {name.lower(), *(a.lower() for a in row["aliases"])}), None)
    meta = {"catalog_version": catalog["version"], "source_url": catalog["source_url"], "source_sha256": catalog["source_sha256"],
            "assessment_status": "family_reference", "limitations": [
                "Không thấy trong sandbox không có nghĩa hành vi không xảy ra; chưa biết nguyên nhân thiếu quan sát.",
                "Ngoài tập tham chiếu không chứng minh biến thể mới; tên họ từ sandbox cũng cần xác minh."]}
    if not family:
        return {**meta, "found": False, "family": None, "matched": [], "not_observed": [], "outside_baseline": []}
    row = catalog["families"][family]
    baseline = {t["id"]: t for t in row["techniques"]}
    observed = {m["technique_id"]: m for m in mappings if m.get("catalog_validation") == "active"}
    matched = [{**baseline[t], "evidence_ids": observed[t]["evidence_ids"], "observation_status": observed[t]["assessment_status"]}
               for t in sorted(baseline.keys() & observed.keys())]
    missing = [{**baseline[t], "assessment_status": "family_reference", "evidence_ids": [],
                "verification": "Kiểm tra log trên máy/mạng thực; không suy diễn hành vi từ tên họ."} for t in sorted(baseline.keys() - observed.keys())]
    outside = [{"id": t, "name": m["name"], "evidence_ids": m["evidence_ids"], "assessment_status": m["assessment_status"]}
               for t, m in observed.items() if t not in baseline]
    return {**meta, "found": True, "family": family, "software_id": row["software_id"], "family_url": row["url"],
            "matched": matched, "not_observed": missing, "outside_baseline": outside}


def enrich_mappings(mappings, story, bundle=None):
    """Process/command and explicit behavior signatures become candidates; DLL/PE/family guesses do not."""
    catalog = catalogue()
    candidates = [f for p in story["processes"] for f in p["command_analysis"]["findings"] + p["flags"] if f.get("technique_id")]
    for e in (bundle or {}).get("evidence", []):
        if e["type"] != "behavior":
            continue
        value = e["value"].lower()
        tid = "T1113" if "functionality for taking screenshot" in value else "T1082" if any(
            text in value for text in ("reads the bios version", "reads the machine guid", "reads the computer name")) else None
        if tid:
            candidates.append({"technique_id": tid, "summary": "Chữ ký nguồn, chưa xác minh sự kiện: " + e["value"],
                               "evidence_ids": [e["id"]], "origin": "behavior_signature_hypothesis"})
    for finding in candidates:
        tid = finding["technique_id"]
        tech = catalog["techniques"].get(tid)
        if not tech or tech["revoked"] or tech["deprecated"]:
            continue
        origin = finding.get("origin", "process_hypothesis")
        key = next((m for m in mappings if m["technique_id"] == tid and m["origin"] == origin), None)
        if key:
            key["evidence_ids"] = list(dict.fromkeys(key["evidence_ids"] + finding["evidence_ids"]))
            continue
        mappings.append({"technique_id": tid, "name": tech["name"], "tactics": tech["tactics"],
                         "evidence_ids": finding["evidence_ids"], "origin": origin, "reason": finding["summary"],
                         "catalog_version": catalog["version"], "catalog_validation": "active", "assessment_status": "hypothesis", "url": tech["url"]})


def build_deep_analysis(report, bundle, mappings, threat):
    story = build_process_story(bundle)
    enrich_mappings(mappings, story, bundle)
    return {"process_story": story, "static_profile": build_static_profile(report, bundle),
            "family_expectations": compare_family(threat, mappings)}


def deep_report_lines(payload):
    """Plain text shared by PDF/HTML/Markdown exporters; callers escape their own format."""
    lines = []
    narrative = ((payload.get("case_agent") or {}).get("assessment") or {}).get("attack_narrative", [])
    if narrative:
        lines.append("Diễn biến cuộc tấn công")
        lines += [f'{r["text"]} [{r["assessment_status"]}; {", ".join(r["evidence_ids"])}]' for r in narrative]
    story = payload.get("process_story") or {}
    for p in story.get("processes", []):
        parent = p.get("parent")
        lines.append(f'Tiến trình {p["name"]} PID {p["pid"]} UUID {p["uuid"]}: {p["path"]} [{p["id"]}]')
        if parent:
            lines.append(f'Cha: {parent["name"]} ({parent["basis"]}) [{", ".join(parent["evidence_ids"])}]')
        for row in p["roles"] + p["flags"] + p["command_analysis"]["findings"]:
            lines.append(f'{row["summary"]} [{row["assessment_status"]}/{row["confidence"]}; {", ".join(row["evidence_ids"])}]')
        if p["command_analysis"]["original"]:
            lines.append("Lệnh nguồn (không thực thi): " + p["command_analysis"]["original"])
        if p["command_analysis"]["decoded_powershell"]:
            lines.append("PowerShell giải mã (không thực thi): " + p["command_analysis"]["decoded_powershell"])
    for row in story.get("drop_execute", []):
        lines.append(f'{row["path"]}: {row["summary"]} [{", ".join(row["evidence_ids"])}]')
    profile = payload.get("static_profile") or {}
    for row in profile.get("findings", []) + profile.get("runtime", []) + profile.get("dll_capabilities", []) + profile.get("trid", []):
        lines.append(f'{row["summary"]} [{row["assessment_status"]}/{row["confidence"]}; {", ".join(row["evidence_ids"])}]')
    if profile:
        lines.append("Chữ ký số: " + profile["signature"]["status"] + ". " + profile["signature"]["note"])
    family = payload.get("family_expectations") or {}
    if family.get("found"):
        lines.append(f'Đối chiếu họ {family["family"]}, ATT&CK {family["catalog_version"]}: {family["family_url"]}')
        for key, label in (("matched", "Khớp ứng viên"), ("not_observed", "Chưa quan sát"), ("outside_baseline", "Ngoài tham chiếu")):
            lines += [f'{label}: {r["id"]} {r["name"]} [{", ".join(r["evidence_ids"])}]' for r in family[key]]
        lines += family["limitations"]
    return lines
