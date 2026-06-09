"""
Helpers for ANY.RUN public HTML reports.

The authenticated JSON API and the public report page expose different shapes.
This module extracts the public page's embedded `window.vueData` payload and
normalizes it into the report shape consumed by MalwareAnalyzer.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import unquote, urlparse

import requests


UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
PUBLIC_REPORT_RE = re.compile(
    r"https?://(?:report\.)?any\.run/report/[0-9a-fA-F]{32,64}/[0-9a-fA-F-]{36}",
    re.IGNORECASE,
)


class AnyRunPublicReportError(Exception):
    pass


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
        return _public_vue_data_to_anyrun_report(_download_public_vue_data(public_url), task_uuid)

    cached = _load_cached_public_vue_data(task_uuid, Path(reports_dir))
    if cached:
        return _public_vue_data_to_anyrun_report(cached, task_uuid)

    if re.search(r"https?://app\.any\.run/tasks/", source_ref, re.IGNORECASE):
        raise AnyRunPublicReportError(
            "Link app.any.run/tasks/<uuid> là trang task cần đăng nhập, không phải public report URL. "
            "Hãy mở task trên Any.Run, chọn Public report/Share rồi dán link dạng "
            "https://any.run/report/<sha256>/<uuid>."
        )

    if source_ref.strip().lower() == task_uuid:
        raise AnyRunPublicReportError(
            "Backend chỉ nhận được Task UUID, không nhận được public report URL đầy đủ. "
            "Hãy restart Flask, nhấn Ctrl+F5 trên trình duyệt rồi dán lại link dạng "
            "https://any.run/report/<sha256>/<uuid>."
        )

    raise AnyRunPublicReportError(
        "Không tìm thấy public report HTML/JSON cho UUID này. Hãy paste link dạng "
        "https://any.run/report/<sha256>/<uuid> hoặc import report từ Any.Run."
    )


def _extract_public_url(value: str) -> str:
    match = PUBLIC_REPORT_RE.search(value or "")
    if not match:
        return ""
    return match.group(0).replace("https://report.any.run/", "https://any.run/")


def _download_public_vue_data(url: str) -> dict:
    try:
        response = requests.get(url, timeout=30, headers={"User-Agent": "Mozilla/5.0"})
    except requests.RequestException as exc:
        raise AnyRunPublicReportError(
            f"Không kết nối được tới public report Any.Run. Kiểm tra mạng, proxy hoặc firewall: {exc}"
        ) from exc
    if response.status_code != 200:
        raise AnyRunPublicReportError(f"Không tải được public report HTML ({response.status_code}).")
    return _extract_vue_data(response.text)


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
    match = re.search(r'window\.vueData="([^"]+)"', html or "")
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
        "publicReport": data,
    }
    return {
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


def _normalize_network(network: dict) -> dict:
    connections = []
    http_requests = []
    dns_requests = []
    for row in network.get("connections", []) or []:
        remote = str(row[2] if len(row) > 2 else "")
        ip = remote.rsplit(":", 1)[0] if ":" in remote else remote
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip):
            connections.append({"ip": ip})
    for row in network.get("requests", []) or []:
        url = str(row[5] if len(row) > 5 else "")
        parsed = urlparse(url)
        http_requests.append(
            {
                "method": str(row[2] if len(row) > 2 else ""),
                "status": row[3] if len(row) > 3 else "",
                "url": url,
                "domain": parsed.hostname or "",
                "userAgent": "",
            }
        )
    for row in network.get("dns", []) or []:
        domain = str(row[0] if row else "")
        dns_requests.append({"domain": domain})
        for ip in row[1] if len(row) > 1 and isinstance(row[1], list) else []:
            connections.append({"ip": ip})
    return {"connections": connections, "httpRequests": http_requests, "dnsRequests": dns_requests}


def _normalize_processes(processes: dict) -> list[dict]:
    normalized = []
    for item in processes.get("processesValues", []) or []:
        row = item.get("rowData") or {}
        values = row.get("values") or []
        normalized.append(
            {
                "pid": item.get("pid") or (values[0] if values else 0),
                "ppid": 0,
                "name": item.get("fileName") or Path(str(values[2] if len(values) > 2 else "")).name,
                "cmd": str(values[1] if len(values) > 1 else ""),
                "isInjected": False,
                "scores": {"verdict": {"threatLevel": row.get("threatLevel", 0)}},
            }
        )
    return normalized


def _normalize_dropped(files: dict) -> list[dict]:
    result = []
    for item in files.get("droppedFiles", []) or []:
        result.append(
            {
                "filename": item.get("filename", ""),
                "hashes": {"md5": item.get("md5", ""), "sha256": item.get("sha256", "")},
                "type": (item.get("type") or {}).get("value", "") if isinstance(item.get("type"), dict) else item.get("type", ""),
            }
        )
    return result


def _normalize_registry(registry: dict) -> list[dict]:
    return [{"key": item.get("key", "")} for item in registry.get("modificationEvents", []) or []]


def _normalize_sync(sync: dict) -> list[dict]:
    values = sync.get("values", []) or []
    return [{"name": item.get("name", str(item)) if isinstance(item, dict) else str(item)} for item in values]


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
                    found[tid] = {"id": tid, "name": name, "tactic": tactic}
    return list(found.values())
