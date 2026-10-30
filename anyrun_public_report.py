"""
Helpers for ANY.RUN public HTML reports.

The authenticated JSON API and the public report page expose different shapes.
This module extracts the public page's embedded `window.vueData` payload and
normalizes it into the report shape consumed by MalwareAnalyzer.
"""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import unquote, urlparse

import requests
from anyrun_public_client import fetch_public_page, resolve_public_task, PublicTaskLookupError


UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
PUBLIC_REPORT_RE = re.compile(
    r"https?://(?:report\.)?any\.run/report/[0-9a-fA-F]{32,64}/[0-9a-fA-F-]{36}",
    re.IGNORECASE,
)


class AnyRunPublicReportError(Exception):
    def __init__(self, message, code="anyrun_public_report_unavailable", status=403):
        super().__init__(message)
        self.code = code
        self.status = status


def extract_task_uuid(value: str) -> str:
    match = UUID_RE.search(value or "")
    return match.group(0).lower() if match else ""


def load_public_report(task_uuid: str, source_ref: str = "", reports_dir: str | Path = "reports") -> dict:
    task_uuid = extract_task_uuid(task_uuid)
    if not task_uuid:
        raise AnyRunPublicReportError("Không tìm thấy UUID trong report public.")

    source_ref = source_ref or ""
    public_url = _extract_public_url(source_ref)
    if public_url:
        data = _download_public_vue_data(public_url)
        if _data_uuid(data) and _data_uuid(data) != task_uuid:
            raise AnyRunPublicReportError('Báo cáo trả về không khớp Task ID đã nhập.', 'anyrun_report_mismatch', 422)
        return _public_vue_data_to_anyrun_report(data, task_uuid)

    cached = _load_cached_public_vue_data(task_uuid, Path(reports_dir))
    if cached:
        return _public_vue_data_to_anyrun_report(cached, task_uuid)

    task_url = _extract_task_url(source_ref, task_uuid)
    if task_url or source_ref.strip().lower() == task_uuid:
        try:
            report_url = resolve_public_task(task_uuid)
        except PublicTaskLookupError as exc:
            raise AnyRunPublicReportError(str(exc), 'anyrun_public_task_unavailable', 403) from exc
        except Exception as exc:
            raise AnyRunPublicReportError('Chưa kết nối được kênh đọc task công khai của Any.Run. Thử lại sau hoặc nhập báo cáo đã xuất.', 'anyrun_task_lookup_failed', 502) from exc
        data = _download_public_vue_data(report_url)
        received_uuid = _data_uuid(data)
        if received_uuid and received_uuid != task_uuid:
            raise AnyRunPublicReportError("Báo cáo trả về không khớp Task ID đã nhập.", "anyrun_report_mismatch", 422)
        return _public_vue_data_to_anyrun_report(data, task_uuid)

    raise AnyRunPublicReportError(
        "Không tìm thấy public report HTML/JSON cho UUID này. Hãy paste link dạng "
        "https://any.run/report/<sha256>/<uuid> hoặc import report từ Any.Run."
    )


def _extract_public_url(value: str) -> str:
    match = PUBLIC_REPORT_RE.search(value or "")
    if not match:
        return ""
    return match.group(0).replace("https://report.any.run/", "https://any.run/")


def _extract_task_url(value: str, expected_uuid: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme not in ("http", "https") or parsed.hostname != "app.any.run":
        return ""
    if not re.fullmatch(r"/tasks/" + re.escape(expected_uuid) + r"/?", parsed.path, re.IGNORECASE):
        return ""
    return "https://app.any.run/tasks/" + expected_uuid


def _download_public_vue_data(url: str) -> dict:
    """Read a public page normally; report access protection without assuming privacy."""
    try:
        response = fetch_public_page(url)
    except Exception as exc:
        raise AnyRunPublicReportError(
            "Không kết nối được tới Any.Run. Kiểm tra mạng, proxy hoặc firewall; "
            "bạn cũng có thể nhập báo cáo Results.md/JSON đã xuất.",
            "anyrun_network_error", 503
        ) from exc
    html = response.text
    if response.status_code == 200:
        try:
            return _extract_vue_data(html)
        except AnyRunPublicReportError:
            pass
    challenge = any(marker in html.lower() for marker in ("/cdn-cgi/challenge-platform/", "cf-chl-"))
    if response.status_code == 403 or challenge:
        detail = "Cloudflare yêu cầu xác minh trình duyệt" if challenge else "Any.Run từ chối yêu cầu từ máy chủ (HTTP 403)"
        raise AnyRunPublicReportError(
            detail + ". Link vẫn có thể xem công khai trong trình duyệt của bạn; "
            "điều đó không đảm bảo máy chủ ứng dụng tải được dữ liệu. "
            "Hãy xuất Results.md hoặc JSON từ Any.Run rồi chọn Nhập báo cáo, "
            "hoặc sử dụng API key có quyền đọc báo cáo.",
            "anyrun_server_access_blocked", 403
        )
    if response.status_code == 404:
        raise AnyRunPublicReportError("Any.Run trả HTTP 404 cho trang báo cáo. Kiểm tra lại liên kết hoặc nhập báo cáo đã xuất.", "anyrun_report_not_found", 404)
    if response.status_code != 200:
        raise AnyRunPublicReportError(f"Máy chủ không tải được trang Any.Run (HTTP {response.status_code}). Thử lại hoặc nhập báo cáo đã xuất.", "anyrun_upstream_error", 502)
    try:
        return _extract_vue_data(html)
    except AnyRunPublicReportError:
        # A task page can link to a server-rendered report. Follow only the
        # matching public report URL on the known ANY.RUN host, at most once.
        if urlparse(url).hostname == "app.any.run":
            report_url = _extract_public_url(html.replace("\\/", "/"))
            if report_url and extract_task_uuid(report_url) == extract_task_uuid(url):
                return _download_public_vue_data(report_url)
        raise AnyRunPublicReportError(
            "Đã tải trang Any.Run nhưng chưa tìm thấy dữ liệu báo cáo có thể đọc tự động. "
            "Trang có thể cần JavaScript hoặc xác minh trong trình duyệt. "
            "Hãy chọn Export trên Any.Run, tải Results.md/JSON và dùng Nhập báo cáo.",
            "anyrun_page_data_unavailable", 422
        )


def _load_cached_public_vue_data(task_uuid: str, reports_dir: Path) -> dict:
    if not reports_dir.exists():
        return {}
    for path in sorted(reports_dir.glob("anyrun_public_report_*.json"), reverse=True):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if _data_uuid(data) == task_uuid:
            return data
    for path in sorted(reports_dir.glob("anyrun_public_report_*.html"), reverse=True):
        try:
            data = _extract_vue_data(path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        if _data_uuid(data) == task_uuid:
            return data
    return {}


def _extract_vue_data(html: str) -> dict:
    match = re.search(r'window\.vueData\s*=\s*"([^"]+)"', html or "")
    if not match:
        raise AnyRunPublicReportError("HTML public report không có window.vueData.")
    try:
        return json.loads(unquote(match.group(1)))
    except Exception as exc:
        raise AnyRunPublicReportError(f"Không parse được window.vueData: {exc}") from exc


def _data_uuid(data: dict) -> str:
    meta_uuid = str((data.get("meta") or {}).get("uuid") or "")
    if meta_uuid:
        return meta_uuid.lower()
    return extract_task_uuid(str((data.get("general") or {}).get("fullAnalysis") or ""))


def _public_vue_data_to_anyrun_report(data: dict, fallback_uuid: str) -> dict:
    general = data.get("general") or {}
    meta = data.get("meta") or {}
    uuid = _data_uuid(data) or fallback_uuid
    hashes = {str(item.get("key", "")).lower(): item.get("value", "") for item in general.get("hashes", []) or []}
    filename = (general.get("mainObject") or {}).get("value") or meta.get("taskName") or "unknown"
    threat_name = _best_threat_name(general)
    threat_level = int((general.get("verdict") or {}).get("type") or 0)

    content = {
        "mainObject": {
            "filename": filename,
            "size": _main_object_size(data),
            "hashes": {
                "md5": hashes.get("md5", ""),
                "sha1": hashes.get("sha1", ""),
                "sha256": hashes.get("sha256", meta.get("sha256", "")),
            },
            "type": general.get("fileInfo", ""),
            "mime": general.get("mime", ""),
        },
        "scores": {
            "verdict": {
                "threatLevel": threat_level,
                "threat": (general.get("verdict") or {}).get("value", "Unknown"),
            },
            "specs": {"knownThreat": threat_name},
        },
        "mitre": _behavior_to_mitre(data.get("behaviorActivities") or []),
        "network": _normalize_network(data.get("networkActivity") or {}),
        "processes": _normalize_processes(data.get("processes") or {}),
        "dropped": _normalize_dropped(data.get("filesActivity") or {}),
        "registry": _normalize_registry(data.get("registryActivity") or {}),
        "synchronization": _normalize_sync(data.get("synchronization") or {}),
        "behaviors": _normalize_behaviors(data.get("behaviorActivities") or []),
        "threatClasses": _normalize_threat_classes(general),
        "indicators": [str(i) for i in general.get("indicators", []) or []],
        "malwareConfig": _normalize_malware_config(data.get("malwareConfiguration") or {}),
    }
    return {
        "publicReport": data,
        "data": {
            "analysis": {
                "uuid": uuid,
                "status": "done",
                "duration": _duration_seconds(general),
                "tags": general.get("tags", []) or meta.get("tags", []) or [],
                "options": {"os": {"version": general.get("os", "Unknown OS")}},
            },
            "content": content,
        }
    }


def _best_threat_name(general: dict) -> str:
    tags = [str(t).lower() for t in general.get("tags", []) or []]
    for family in ("wannacry", "emotet", "redline", "agenttesla", "lumma", "formbook", "qakbot"):
        if family in tags:
            return {"wannacry": "WannaCry", "redline": "RedLine Stealer"}.get(family, family.title())
    threats = general.get("threats", []) or []
    for item in threats:
        title = str(item.get("title") or "")
        if title and title.lower() not in {"ransomware", "trojan", "malware"}:
            return title
    return threats[0].get("title", "") if threats else ""


def _duration_seconds(general: dict) -> int:
    for item in ((general.get("launchConfiguration") or {}).get("nameValues") or []):
        if str(item.get("name", "")).lower().startswith("task duration"):
            match = re.search(r"\d+", str(item.get("value", "")))
            return int(match.group(0)) if match else 0
    return 0


def _main_object_size(data: dict) -> int:
    for group in (data.get("staticInformation") or {}).get("exif", []) or []:
        for key, value in (group[1] if len(group) > 1 else []):
            if str(key).lower() in {"zipuncompressedsize", "zipcompressedsize"}:
                try:
                    return int(value)
                except Exception:
                    return 0
    return 0


PID_SUFFIX_RE = re.compile(r"^(.*?)\s*\(PID:\s*(\d+)\)\s*$")


def _at(row, index, default=""):
    return row[index] if isinstance(row, list) and len(row) > index else default


def _text(value, limit=2000) -> str:
    """Public report cells use an em dash for "no value"; keep everything else as text."""
    if value is None or value in ("—", "-"):
        return ""
    return str(value)[:limit]


def _label(value) -> str:
    return _text(value.get("value", "")) if isinstance(value, dict) else _text(value)


def _pid(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _endpoint(value) -> tuple[str, int | None]:
    text = _text(value)
    host, sep, port = text.rpartition(":")
    if sep and port.isdigit():
        return host.strip("[]"), int(port)
    return text, None


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _normalize_network(network: dict) -> dict:
    """Keep who connected where: PID/process, port, ASN, country and ANY.RUN reputation."""
    connections, http_requests, dns_requests, alerts = [], [], [], []
    for row in network.get("connections", []) or []:
        ip, port = _endpoint(_at(row, 2))
        if not _is_ip(ip):
            continue
        connections.append({"ip": ip, "port": port, "pid": _pid(_at(row, 0)), "process": _text(_at(row, 1)),
                            "domain": _text(_at(row, 3)), "asn": _text(_at(row, 4)), "country": _text(_at(row, 5)),
                            "reputation": _label(_at(row, 6))})
    for row in network.get("requests", []) or []:
        url = _text(_at(row, 5))
        ip, port = _endpoint(_at(row, 4))
        http_requests.append({"pid": _pid(_at(row, 0)), "process": _text(_at(row, 1)), "method": _text(_at(row, 2)),
                              "status": _text(_at(row, 3)), "ip": ip if _is_ip(ip) else "", "port": port,
                              "url": url, "domain": urlparse(url).hostname or "", "country": _text(_at(row, 6)),
                              "contentType": _label(_at(row, 7)), "size": _text(_at(row, 8)),
                              "reputation": _label(_at(row, 9)), "userAgent": ""})
    for row in network.get("dns", []) or []:
        answers = _at(row, 1, [])
        # Resolved addresses stay attached to their domain; resolving is not the same as connecting.
        dns_requests.append({"domain": _text(_at(row, 0)),
                             "ips": [str(ip) for ip in answers if _is_ip(str(ip))] if isinstance(answers, list) else [],
                             "reputation": _label(_at(row, 2))})
    for row in network.get("threats", []) or []:
        alerts.append({"pid": _pid(_at(row, 0)), "process": _text(_at(row, 1)), "class": _label(_at(row, 2)),
                       "message": _text(_at(row, 3))})
    return {"connections": connections, "httpRequests": http_requests, "dnsRequests": dns_requests, "alerts": alerts}


def _normalize_processes(processes: dict) -> list[dict]:
    rows = []
    for item in processes.get("processesValues", []) or []:
        row = item.get("rowData") or {}
        values = row.get("values") or []
        info = (row.get("information") or {}).get("values") or []
        path = _text(_at(values, 2))
        indicators = _at(values, 3, [])
        rows.append({
            "pid": _pid(item.get("pid") or _at(values, 0)) or 0,
            "ppid": None,
            "parentName": _text(_at(values, 4)),
            "name": item.get("fileName") or Path(path.replace("\\", "/")).name,
            "path": path,
            "cmd": _text(_at(values, 1), 4000),
            "indicators": [str(i) for i in indicators] if isinstance(indicators, list) else [],
            "user": _text(_at(info, 0)), "company": _text(_at(info, 1)), "integrity": _text(_at(info, 2)),
            "description": _text(_at(info, 3)),
            "isInjected": None,
            "scores": {"verdict": {"threatLevel": row.get("threatLevel", 0)}},
        })
    # The public page names the parent but not its PID. Link only when that name is unique,
    # and say so, rather than guessing between several processes with the same name.
    by_name = {}
    for row in rows:
        by_name.setdefault(row["name"].lower(), []).append(row["pid"])
    for row in rows:
        candidates = by_name.get(row["parentName"].lower(), [])
        if len(candidates) == 1 and candidates[0] != row["pid"]:
            row["ppid"] = candidates[0]
            row["ppidBasis"] = "unique_parent_name"
    return rows


def _normalize_dropped(files: dict) -> list[dict]:
    result = []
    for item in files.get("droppedFiles", []) or []:
        result.append({
            "filename": _text(item.get("filename", "")),
            "pid": _pid(item.get("pid")), "process": _text(item.get("process", "")),
            "hashes": {"md5": _text(item.get("md5", "")), "sha256": _text(item.get("sha256", ""))},
            "type": _label(item.get("type") or ""),
        })
    return result


def _normalize_registry(registry: dict) -> list[dict]:
    rows = []
    for item in registry.get("modificationEvents", []) or []:
        if not isinstance(item, dict):
            continue
        row = {k: _text(item.get(k, "")) for k in ("key", "name", "value", "operation", "process")}
        row["pid"] = _pid(item.get("pid"))
        rows.append(row)
    return rows


def _normalize_sync(sync: dict) -> list[dict]:
    values = sync.get("values", []) or []
    return [{"name": item.get("name", str(item)) if isinstance(item, dict) else str(item)} for item in values]


def _normalize_behaviors(groups: list) -> list[dict]:
    """ANY.RUN behaviour signatures, e.g. "Deletes shadow copies", with the processes that showed them."""
    rows = []
    for group in groups or []:
        if not isinstance(group, dict):
            continue
        severity = _text(group.get("name", "")).lower()
        for behavior in group.get("values", []) or []:
            if not isinstance(behavior, dict) or not _text(behavior.get("name", "")):
                continue
            processes = []
            for value in behavior.get("values", []) or []:
                match = PID_SUFFIX_RE.match(str(value))
                processes.append({"name": match.group(1), "pid": int(match.group(2))} if match
                                 else {"name": _text(value), "pid": None})
            rows.append({"severity": severity, "name": _text(behavior.get("name", "")), "processes": processes[:50]})
    return rows


def _normalize_threat_classes(general: dict) -> list[dict]:
    return [{"title": _text(item.get("title", "")), "tag": _text(item.get("mainTag", ""))}
            for item in general.get("threats", []) or [] if isinstance(item, dict)]


def _normalize_malware_config(config: dict) -> list[str]:
    # Extracted configs vary by family; keep them as bounded JSON text for evidence and the agent.
    return [json.dumps(item, ensure_ascii=False)[:4000] for item in (config or {}).get("familiesMalconfs", []) or []][:10]


def _behavior_to_mitre(groups: list[dict]) -> list[dict]:
    mapping = [
        ("powershell", "T1059.001", "PowerShell", "Execution"),
        ("defender exclusion", "T1562.001", "Impair Defenses", "Defense Evasion"),
        ("defender settings", "T1562.001", "Impair Defenses", "Defense Evasion"),
        ("autorun", "T1547.001", "Registry Run Keys / Startup Folder", "Persistence"),
        ("startup directory", "T1547.001", "Registry Run Keys / Startup Folder", "Persistence"),
        ("task scheduler", "T1053.005", "Scheduled Task", "Persistence"),
        ("base64", "T1027", "Obfuscated Files or Information", "Defense Evasion"),
        ("steals credentials", "T1555.003", "Credentials from Web Browsers", "Credential Access"),
        ("ransom", "T1486", "Data Encrypted for Impact", "Impact"),
        ("wannacry", "T1486", "Data Encrypted for Impact", "Impact"),
        ("cryptolocker", "T1486", "Data Encrypted for Impact", "Impact"),
    ]
    found = {}
    for group in groups:
        for behavior in group.get("values", []) or []:
            text = str(behavior.get("name", "")).lower()
            for needle, tid, name, tactic in mapping:
                if needle in text:
                    found[tid] = {"id": tid, "name": name, "tactic": tactic,
                                  "origin": "adapter_keyword_hypothesis", "evidence_text": behavior.get("name", "")}
    return list(found.values())
