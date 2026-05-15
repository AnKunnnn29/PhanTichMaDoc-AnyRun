"""
markdown_importer.py
~~~~~~~~~~~~~~~~~~~~
Convert a manually exported ANY.RUN Results/Text Report markdown file into the
small JSON shape consumed by MalwareAnalyzer.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse


_TECHNIQUE_MAP = {
    "T1053": ("Scheduled Task/Job", "Persistence"),
    "T1055": ("Process Injection", "Defense Evasion"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1112": ("Modify Registry", "Defense Evasion"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1082": ("System Information Discovery", "Discovery"),
    "T1083": ("File and Directory Discovery", "Discovery"),
    "T1204": ("User Execution", "Execution"),
    "T1486": ("Data Encrypted for Impact", "Impact"),
    "T1490": ("Inhibit System Recovery", "Impact"),
    "T1562": ("Impair Defenses", "Defense Evasion"),
    "T1543": ("Create or Modify System Process", "Persistence"),
    "T1547": ("Boot or Logon Autostart Execution", "Persistence"),
    "T1566": ("Phishing", "Initial Access"),
}

_DOMAIN_SKIP = {
    "any.run",
    "app.any.run",
    "www.any.run",
    "attack.mitre.org",
    "virustotal.com",
    "www.virustotal.com",
}

_DOMAIN_SKIP_TLDS = {"exe", "dll", "bin", "bat", "cmd", "ps1", "js", "vbs", "lnk", "doc", "docx", "pdf", "md", "txt"}


def markdown_to_anyrun_report(markdown_text: str, source_name: str = "Results.md") -> dict:
    """Best-effort parser for ANY.RUN markdown/text report exports."""
    text = markdown_text or ""
    lower = text.lower()

    task_uuid = _first_match(r"app\.any\.run/tasks/([0-9a-fA-F-]{36})", text)
    if not task_uuid:
        task_uuid = _first_match(r"\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b", text)
    task_uuid = task_uuid or "manual-markdown-import"

    sha256_entries = _extract_sha256_entries(text)
    md5 = _first_hash(text, "md5", 32)
    sha1 = _first_hash(text, "sha1", 40)
    sha256 = _first_hash(text, "sha256", 64)
    filename = _extract_filename(text) or source_name
    if sha256_entries:
        main_entry = _select_main_sha256_entry(sha256_entries, filename)
        if main_entry:
            filename = _clean_markdown_value(main_entry["path"])
            sha256 = main_entry["sha256"]

    urls = _unique(re.findall(r"https?://[^\s\]\)>'\"`]+", text, flags=re.IGNORECASE))
    network_urls = [url for url in urls if (urlparse(url).hostname or "").lower() not in _DOMAIN_SKIP]
    ips = _unique(re.findall(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", text))
    domains = _extract_domains(text, network_urls)

    mitre_ids = _unique(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text, flags=re.IGNORECASE))
    mitre_ids = _unique(mitre_ids + _infer_mitre_ids(lower))

    mitre = []
    for tid in mitre_ids:
        base_id = tid.upper().split(".")[0]
        name, tactic = _TECHNIQUE_MAP.get(base_id, (f"MITRE ATT&CK {tid.upper()}", "Unknown"))
        mitre.append({"id": tid.upper(), "name": name, "tactic": tactic})

    processes = [
        {"pid": 0, "ppid": 0, "name": name, "cmd": name, "isInjected": False, "scores": {"verdict": {"threatLevel": 1}}}
        for name in _unique(re.findall(r"\b[\w.-]+\.exe\b", text, flags=re.IGNORECASE))[:30]
    ]

    registry = [{"key": key} for key in _unique(re.findall(r"\bHK(?:LM|CU|CR|U|CC)\\[^\s`|]+", text, flags=re.IGNORECASE))[:30]]
    dropped_paths = _extract_windows_paths(text)
    dropped_by_name = {
        path.lower(): {"filename": path, "hashes": {}, "type": "Extracted from markdown report"}
        for path in dropped_paths[:30]
    }
    for entry in sha256_entries:
        path = _clean_markdown_value(entry["path"])
        if path and path != filename and ("\\" in path or "/" in path):
            dropped_by_name[path.lower()] = {
                "filename": path,
                "hashes": {"sha256": entry["sha256"]},
                "type": "Copied from ANY.RUN indicators",
            }
    dropped = list(dropped_by_name.values())

    threat_level = _infer_threat_level(lower)
    verdict = "Malicious" if threat_level >= 2 else "Suspicious" if threat_level == 1 else "Unknown"
    threat_name = _extract_threat_name(text) or _guess_threat_name(text)
    tags = [tag.lower() for tag in [threat_name] if tag]

    return {
        "data": {
            "analysis": {
                "uuid": task_uuid,
                "duration": 0,
                "tags": tags,
                "status": "done",
                "options": {"os": {"version": _extract_os(text) or "Unknown OS"}},
            },
            "content": {
                "mainObject": {
                    "filename": filename,
                    "size": 0,
                    "type": "ANY.RUN Results markdown",
                    "mime": "text/markdown",
                    "hashes": {"md5": md5, "sha1": sha1, "sha256": sha256},
                },
                "scores": {
                    "verdict": {"threatLevel": threat_level, "threat": verdict},
                    "specs": {"knownThreat": threat_name},
                },
                "mitre": mitre,
                "network": {
                    "connections": [{"ip": ip, "port": 0, "protocol": ""} for ip in ips],
                    "httpRequests": [{"method": "", "url": url, "domain": urlparse(url).hostname or "", "status": "", "userAgent": ""} for url in network_urls],
                    "dnsRequests": [{"domain": domain} for domain in domains],
                },
                "processes": processes,
                "registry": registry,
                "dropped": dropped,
                "synchronization": [],
            },
        }
    }


def _first_match(pattern: str, text: str) -> str:
    match = re.search(pattern, text, flags=re.IGNORECASE)
    return match.group(1) if match else ""


def _first_hash(text: str, label: str, length: int) -> str:
    labelled = re.search(rf"{label}\s*[:=|]\s*([a-fA-F0-9]{{{length}}})", text, flags=re.IGNORECASE)
    if labelled:
        return labelled.group(1).lower()
    any_hash = re.search(rf"\b[a-fA-F0-9]{{{length}}}\b", text)
    return any_hash.group(0).lower() if any_hash else ""


def _extract_sha256_entries(text: str) -> list[dict[str, str]]:
    entries = []
    for line in text.splitlines():
        match = re.search(r"\bsha256\b\s+(.+?)\s+([a-fA-F0-9]{64})\b", line, flags=re.IGNORECASE)
        if match:
            entries.append({"path": _clean_markdown_value(match.group(1)), "sha256": match.group(2).lower()})
    return entries


def _select_main_sha256_entry(entries: list[dict[str, str]], filename: str) -> dict[str, str] | None:
    if not entries:
        return None
    filename_lower = filename.lower()
    for entry in entries:
        path = entry["path"].lower()
        if filename_lower and filename_lower in path and "\\" not in path and "/" not in path:
            return entry
    for entry in entries:
        path = entry["path"]
        if "\\" not in path and "/" not in path:
            return entry
    return entries[0]


def _extract_filename(text: str) -> str:
    patterns = [
        r"(?:file\s*name|filename|sample|object|name)\s*[:=|]\s*`?([^`\n\r|]+)",
        r"\b([\w .@()-]+\.(?:exe|dll|docm?|xlsm?|pdf|js|vbs|ps1|bat|cmd|scr|zip|rar|bin))\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            return _clean_markdown_value(match.group(1))
    return ""


def _extract_domains(text: str, urls: list[str]) -> list[str]:
    domains = []
    for url in urls:
        host = urlparse(url).hostname or ""
        if host:
            domains.append(host.lower())
    domains.extend(re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", text))
    clean_domains = []
    for domain in _unique([d.lower().strip(".") for d in domains]):
        suffix = domain.rsplit(".", 1)[-1]
        if domain not in _DOMAIN_SKIP and suffix not in _DOMAIN_SKIP_TLDS:
            clean_domains.append(domain)
    return clean_domains


def _extract_windows_paths(text: str) -> list[str]:
    pattern = r"[A-Za-z]:\\[^\r\n|`<>\"']+\.(?:exe\.lnk|tmp\.dmp|docx|docm|xlsx|xlsm|exe|dll|dmp|dat|tmp|ps1|js|vbs|bat|cmd|lnk|bin|pdf)"
    return _unique([p.strip() for p in re.findall(pattern, text, flags=re.IGNORECASE)])


def _extract_threat_name(text: str) -> str:
    patterns = [
        r"(?:known\s+threat|malware\s+family|family|classification)\s*[:=|]\s*`?([^`\n\r|]+)",
        r"(?:main\s+analyzed\s+object|file\s*name|filename|sample|object|name)\s*[:=|]\s*`?([^`\n\r|]+)",
        r"\b(WannaCry|Emotet|RedLine|AgentTesla|Lumma|FormBook|AsyncRAT|Remcos|QakBot)\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            value = match.group(1).strip()
            value = _clean_markdown_value(value)
            guessed = _guess_threat_name(value)
            return guessed if guessed != "Manual ANY.RUN Import" else value
    return ""


def _infer_threat_level(lower_text: str) -> int:
    critical_terms = [
        "danger",
        "malicious activity",
        "ransomware",
        "encrypt",
        "encrypted files",
        "ransom note",
        "disable windows defender",
        "impair defenses",
    ]
    suspicious_terms = ["suspicious", "persistence", "scheduled task", "powershell", "registry"]
    if any(term in lower_text for term in critical_terms):
        return 3
    if "malicious" in lower_text:
        return 2
    if any(term in lower_text for term in suspicious_terms):
        return 1
    return 0


def _infer_mitre_ids(lower_text: str) -> list[str]:
    inferred = []
    if any(term in lower_text for term in ["opened by the user", "launched manually", "archive opened", "user opened"]):
        inferred.append("T1204")
    if any(term in lower_text for term in ["powershell", "execution policy", "obfuscated command"]):
        inferred.append("T1059.001")
    if any(term in lower_text for term in ["cmd", "command prompt"]):
        inferred.append("T1059.003")
    if any(term in lower_text for term in ["scheduled task", "schtasks", "onlogon"]):
        inferred.append("T1053.005")
    if any(term in lower_text for term in ["startup directory", "startup folder"]):
        inferred.append("T1547.001")
    if any(term in lower_text for term in ["registry", "modify registry"]):
        inferred.append("T1112")
    if any(term in lower_text for term in ["disable windows defender", "defender settings", "bypass execution policies", "security features"]):
        inferred.append("T1562.001")
    if any(term in lower_text for term in ["encrypt files", "encrypted files", "ransomware", "ransom note"]):
        inferred.append("T1486")
    if any(term in lower_text for term in ["system files", "windows installation", "discovery"]):
        inferred.append("T1082")
    return inferred


def _guess_threat_name(text: str) -> str:
    known = ["WannaCry", "Emotet", "RedLine", "AgentTesla", "Lumma", "FormBook", "AsyncRAT", "Remcos", "QakBot"]
    lower = text.lower()
    for name in known:
        if name.lower() in lower:
            return name
    return "Manual ANY.RUN Import"


def _extract_os(text: str) -> str:
    match = re.search(r"Windows\s+(?:7|8|10|11|Server)[^\n\r|`]*", text, flags=re.IGNORECASE)
    return match.group(0).strip() if match else ""


def _clean_markdown_value(value: str) -> str:
    clean = value.strip()
    clean = re.sub(r"^\s*[-*]+\s*", "", clean)
    clean = clean.strip("`*_ ")
    clean = re.sub(r"\s*\([^)]*\)\s*$", "", clean).strip()
    return clean.strip("`*_ ")


def _unique(values: list[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        clean = value.strip()
        key = clean.lower()
        if clean and key not in seen:
            seen.add(key)
            result.append(clean)
    return result
