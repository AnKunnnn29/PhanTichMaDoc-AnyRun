"""Conservative, section-aware text import. Preserve source; never invent events from mentions."""
from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit


def _value(text, labels):
    match = re.search(rf"(?im)^\s*(?:[-*]\s*)?(?:{labels})\s*[:=|]\s*`?([^\r\n|`]+)", text)
    return match.group(1).strip().strip("*_ ") if match else ""


def markdown_to_anyrun_report(markdown_text: str, source_name: str = "Results.md") -> dict:
    text = (markdown_text or "").strip()
    if not text:
        raise ValueError("Báo cáo Markdown rỗng")
    sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
    match = re.search(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", text, re.I)
    task = match.group(0).lower() if match else "manual-" + sha[:24]
    family = _value(text, r"known threat|malware family|family|classification")
    verdict_text = _value(text, r"verdict|threat verdict").lower()
    level = {"malicious": 2, "suspicious": 1, "clean": 0, "no threats detected": 0, "benign": 0}.get(verdict_text)
    verdict = "Malicious" if level == 2 else "Suspicious" if level == 1 else "No threats detected" if level == 0 else "Unknown"
    hashes = {}
    for algo, size in (("md5", 32), ("sha1", 40), ("sha256", 64)):
        value = _value(text, algo)
        hashes[algo] = value.lower() if re.fullmatch(r"[0-9a-f]{%d}" % size, value, re.I) else ""
    content = {"mainObject": {"filename": _value(text, r"file\s*name|filename|main analyzed object|sample") or source_name,
                              "size": 0, "type": "ANY.RUN text report", "mime": "text/markdown", "hashes": hashes},
               "scores": {"verdict": {"threat": verdict}, "specs": {"knownThreat": family}},
               "mitre": [], "network": {"connections": [], "httpRequests": [], "dnsRequests": []},
               "processes": [], "dropped": [], "registry": [], "synchronization": []}
    if level is not None:
        content["scores"]["verdict"]["threatLevel"] = level
    sections = {"network": ("network", "connections", "http requests", "dns", "ip addresses", "domains", "urls", "iocs", "indicators"),
                "processes": ("processes", "process tree", "process activity"), "dropped": ("dropped files", "files activity", "created files"),
                "registry": ("registry",), "mitre": ("mitre", "att&ck"), "synchronization": ("mutex", "synchronization")}
    section = ""
    for number, line in enumerate(text.splitlines(), 1):
        heading = re.match(r"^\s*#{1,6}\s+(.+)", line)
        if heading:
            title = heading.group(1).lower()
            section = next((key for key, labels in sections.items() if any(label in title for label in labels)), "")
            continue
        if not section or re.search(r"\b(no|not|without|none|never)\s+|^\s*(reference|documentation|example)\s*[: ]|không|chưa", line, re.I):
            continue
        meta = {"source_line": number, "observation": "reported"}
        if section == "network":
            for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line):
                content["network"]["connections"].append({"ip": ip, **meta})
            for url in re.findall(r"https?://[^\s|`<>\"\]\)]+", line):
                host = urlsplit(url).hostname or ""
                if host not in {"any.run", "app.any.run", "attack.mitre.org", "www.virustotal.com"}:
                    content["network"]["httpRequests"].append({"url": url, "domain": host, **meta})
            for domain in re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", line, re.I):
                if domain.rsplit(".", 1)[-1].lower() not in {"exe", "dll", "doc", "docx", "pdf", "txt", "bin", "ps1"} and domain not in {"any.run", "app.any.run", "attack.mitre.org", "www.virustotal.com"}:
                    content["network"]["dnsRequests"].append({"domain": domain, **meta})
        else:
            patterns = {"processes": (r"\b[\w.-]+\.exe\b", "name"), "dropped": (r"[A-Za-z]:\\[^\r\n|`<>\"]+?\.(?:exe|dll|tmp|dat|lnk|ps1|bin)\b", "filename"),
                        "registry": (r"\bHK(?:LM|CU|CR|U|CC)\\[^\s|`]+", "key"), "mitre": (r"\bT\d{4}(?:\.\d{3})?\b", "id"),
                        "synchronization": (r"[^|`]+", "name")}
            pattern, field = patterns[section]
            for value in re.findall(pattern, line, re.I):
                row = {field: value.strip(), **meta}
                if section == "processes":
                    row.update(pid=None, ppid=None, isInjected=None)
                content[section].append(row)
    return {"data": {"analysis": {"uuid": task, "duration": 0, "status": "done", "tags": [],
                                  "options": {"os": {"version": _value(text, r"os|operating system") or "Unknown OS"}}}, "content": content},
            "import_metadata": {"format": "markdown", "source_name": source_name, "original_text": text, "sha256": sha,
                                "warnings": ["Chỉ đọc trường/mục có nhãn; trường thiếu không chứng minh hành vi vắng mặt.",
                                             "Dữ kiện text được báo cáo, cần đối chiếu JSON/event log."]}}
