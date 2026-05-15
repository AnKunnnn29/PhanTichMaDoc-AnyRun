from __future__ import annotations

import copy
import datetime as _dt
import json
import os
import re
import threading
from typing import Any


_LOCK = threading.Lock()
_HISTORY_PATH = os.path.join(os.getcwd(), "reports", "analysis_history.json")
_GENERIC_FAMILIES = {
    "",
    "unknown",
    "unknown malware",
    "manual any.run import",
    "windows.desktop",
    "windows",
    "desktop",
}


def load_history() -> list[dict[str, Any]]:
    with _LOCK:
        return _read_history()


def record_analysis(payload: dict[str, Any], source: str = "") -> dict[str, Any]:
    entry = _entry_from_payload(payload, source)
    if not entry["family_key"] and not entry["hashes"] and not entry["task_uuid"]:
        return entry

    with _LOCK:
        items = _read_history()
        items = [i for i in items if i.get("id") != entry["id"]]
        items.insert(0, entry)
        _write_history(items[:100])
    return entry


def find_exact_cached_payload(task_uuid: str = "", hashes: list[str] | None = None) -> dict[str, Any] | None:
    hashes = {h.lower() for h in hashes or [] if h}
    with _LOCK:
        for item in _read_history():
            if task_uuid and item.get("task_uuid") == task_uuid:
                return _cached_payload(item, "Trung Task UUID da phan tich")
            if hashes and hashes.intersection({h.lower() for h in item.get("hashes", [])}):
                return _cached_payload(item, "Trung hash file da phan tich")
    return None


def find_family_cached_payload(family_name: str, current_task_uuid: str = "", hashes: list[str] | None = None) -> dict[str, Any] | None:
    family_key = malware_family_key(family_name)
    if family_key in _GENERIC_FAMILIES:
        return None

    hashes = {h.lower() for h in hashes or [] if h}
    with _LOCK:
        for item in _read_history():
            if item.get("family_key") != family_key:
                continue
            if current_task_uuid and item.get("task_uuid") == current_task_uuid:
                continue
            if hashes and hashes.intersection({h.lower() for h in item.get("hashes", [])}):
                continue
            return _cached_payload(item, f"Loai malware '{family_name}' da co trong lich su")
    return None


def extract_hashes_from_report(report_json: dict[str, Any], ioc_json: dict[str, Any] | None = None) -> list[str]:
    hashes: list[str] = []
    data = (report_json or {}).get("data", {})
    content = data.get("content", {})
    main_hashes = (content.get("mainObject", {}) or {}).get("hashes", {}) or {}
    for algo in ("md5", "sha1", "sha256"):
        value = main_hashes.get(algo, "")
        if value:
            hashes.append(value)

    for item in _iter_ioc_items(ioc_json):
        if str(item.get("type", "")).lower() in ("md5", "sha1", "sha256"):
            value = item.get("value", "")
            if value:
                hashes.append(value)
    return _unique(hashes)


def task_uuid_from_report(report_json: dict[str, Any]) -> str:
    return (
        ((report_json or {}).get("data", {}).get("analysis", {}) or {}).get("uuid", "")
        or ""
    )


def malware_family_key(name: str) -> str:
    value = re.sub(r"[^a-z0-9.]+", " ", str(name or "").lower()).strip()
    aliases = {
        "wannacry ransomware": "wannacry",
        "wanna cry": "wannacry",
        "wanacry": "wannacry",
        "wanacrypt": "wannacry",
        "redline": "redline stealer",
    }
    return aliases.get(value, value)


def _entry_from_payload(payload: dict[str, Any], source: str) -> dict[str, Any]:
    file_info = payload.get("file") or {}
    threat = payload.get("threat") or {}
    playbook = payload.get("playbook") or {}
    malware_name = playbook.get("malware_name") or threat.get("threat_name") or "Unknown Malware"
    hashes = _unique(
        [
            file_info.get("md5", ""),
            file_info.get("sha1", ""),
            file_info.get("sha256", ""),
            *[str(h) for h in (playbook.get("ioc_blocklist", {}) or {}).get("file_hashes", [])],
        ]
    )
    task_uuid = payload.get("task_uuid", "")
    entry_id = file_info.get("sha256") or task_uuid or f"{malware_family_key(malware_name)}:{_now_iso()}"
    return {
        "id": entry_id,
        "created_at": _now_iso(),
        "source": source,
        "task_uuid": task_uuid,
        "malware_name": malware_name,
        "family_key": malware_family_key(malware_name),
        "file_name": file_info.get("name", ""),
        "hashes": hashes,
        "verdict": threat.get("verdict", ""),
        "threat_level": threat.get("threat_level", 0),
        "analysis_url": payload.get("analysis_url", ""),
        "payload": copy.deepcopy(payload),
    }


def _cached_payload(entry: dict[str, Any], reason: str) -> dict[str, Any] | None:
    payload = copy.deepcopy(entry.get("payload"))
    if not isinstance(payload, dict):
        return None
    payload["cache"] = {
        "hit": True,
        "reason": reason,
        "matched_at": entry.get("created_at", ""),
        "matched_malware": entry.get("malware_name", ""),
        "matched_task_uuid": entry.get("task_uuid", ""),
    }
    return payload


def _iter_ioc_items(ioc_json: dict[str, Any] | list[Any] | None) -> list[dict[str, Any]]:
    if isinstance(ioc_json, list):
        items = ioc_json
    elif isinstance(ioc_json, dict):
        items = ioc_json.get("data", []) or ioc_json.get("iocs", []) or []
    else:
        items = []
    return [i for i in items if isinstance(i, dict)]


def _read_history() -> list[dict[str, Any]]:
    if not os.path.exists(_HISTORY_PATH):
        return []
    try:
        with open(_HISTORY_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _write_history(items: list[dict[str, Any]]) -> None:
    os.makedirs(os.path.dirname(_HISTORY_PATH), exist_ok=True)
    with open(_HISTORY_PATH, "w", encoding="utf-8") as fh:
        json.dump(items, fh, ensure_ascii=False, indent=2)


def _unique(values: list[str]) -> list[str]:
    seen = set()
    out = []
    for value in values:
        clean = str(value or "").strip()
        if clean and clean.lower() not in seen:
            seen.add(clean.lower())
            out.append(clean)
    return out


def _now_iso() -> str:
    return _dt.datetime.now().replace(microsecond=0).isoformat()
