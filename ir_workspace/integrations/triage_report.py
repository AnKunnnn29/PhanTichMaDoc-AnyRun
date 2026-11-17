"""Convert Recorded Future Triage reports to the report shape the analysis pipeline reads.

Input is the overview report (`/samples/{id}/overview.json`) and, when available, the
per-task dynamic reports (`/samples/{id}/{task}/report_triage.json`). Field names follow
https://tria.ge/docs/cloud-api/overview-report/ and .../dynamic-report/. Everything is
read defensively: the JSON may also be uploaded by hand, so it is untrusted input.
"""
from __future__ import annotations

import json
import re

SAMPLE_ID_RE = re.compile(r"[0-9]{6}-[a-z0-9]{6,16}")
TTP_RE = re.compile(r"T\d{4}(?:\.\d{3})?")
IP_PORT_RE = re.compile(r"^\[?([0-9a-fA-F:.]+?)\]?:(\d{1,5})$")
MAX_ROWS = 5000


class TriageReportError(ValueError):
    pass


def _dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _rows(value) -> list[dict]:
    """A list of objects. The docs show `tasks` both as an array and as an object keyed by id."""
    if isinstance(value, dict):
        value = [{**row, "name": row.get("name") or key} for key, row in value.items() if isinstance(row, dict)]
    return [row for row in value if isinstance(row, dict)][:MAX_ROWS] if isinstance(value, list) else []


def _strings(value, limit: int = 200) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item)[:500] for item in value if isinstance(item, (str, int))][:limit]


def _text(value, limit: int = 2000) -> str:
    return str(value)[:limit] if isinstance(value, (str, int, float)) else ""


def is_triage_report(document) -> bool:
    """An overview report: a `sample` with hashes and no Any.Run `data` envelope."""
    if not isinstance(document, dict) or "data" in document:
        return False
    sample = _dict(document.get("sample"))
    return bool(sample.get("sha256")) and any(key in document for key in ("analysis", "targets", "tasks"))


def _endpoint(value) -> tuple[str, int | None]:
    match = IP_PORT_RE.match(_text(value))
    return (match.group(1), int(match.group(2))) if match else (_text(value), None)


def _basename(path: str) -> str:
    return path.replace("/", "\\").rsplit("\\", 1)[-1]


def _threat_level(score) -> int:
    score = score if isinstance(score, int) else 0
    return 2 if score >= 8 else 1 if score >= 5 else 0


def _signatures(overview: dict, dynamics: list[dict]) -> list[dict]:
    """Dynamic reports carry indicators and TTPs; the overview is the fallback."""
    found = {}
    pools = [_rows(d.get("signatures")) for d in dynamics] + [_rows(overview.get("signatures"))]
    pools += [_rows(target.get("signatures")) for target in _rows(overview.get("targets"))]
    for pool in pools:
        for row in pool:
            name = _text(row.get("name") or row.get("label"), 300)
            if not name:
                continue
            entry = found.setdefault(name, {"name": name, "score": 0, "ttp": [], "desc": "", "pids": []})
            entry["score"] = max(entry["score"], row.get("score") if isinstance(row.get("score"), int) else 0)
            entry["desc"] = entry["desc"] or _text(row.get("desc"), 500)
            entry["ttp"] += [t for t in _strings(row.get("ttp")) if TTP_RE.fullmatch(t) and t not in entry["ttp"]]
            for indicator in _rows(row.get("indicators")):
                pid = indicator.get("pid")
                if isinstance(pid, int) and pid not in entry["pids"]:
                    entry["pids"].append(pid)
    return list(found.values())[:500]


def _network(overview: dict, dynamics: list[dict]) -> dict:
    connections, http_requests, dns = [], [], {}
    for dynamic in dynamics:
        network = _dict(dynamic.get("network"))
        flows = {}
        for flow in _rows(network.get("flows")):
            ip, port = _endpoint(flow.get("dst"))
            flows[flow.get("id")] = (ip, port, flow.get("pid") if isinstance(flow.get("pid"), int) else None)
            if port == 53:
                continue  # the sandbox's DNS resolver is transport, not a destination the sample chose
            connections.append({"ip": ip, "port": port, "pid": flows[flow.get("id")][2], "process": "",
                                "domain": _text(flow.get("domain"), 253), "asn": _text(flow.get("as_org"), 200),
                                "country": _text(flow.get("country"), 8), "reputation": ""})
        for request in _rows(network.get("requests")):
            ip, port, pid = flows.get(request.get("flow"), ("", None, None))
            for part in ("dns_request", "dns_response"):
                block = _dict(request.get(part))
                for domain in _strings(block.get("domains")):
                    dns.setdefault(domain, [])
                    dns[domain] += [a for a in _strings(block.get("ip")) if a not in dns[domain]]
            http = _dict(request.get("http_request"))
            url = _text(http.get("url"))
            if url:
                agent = next((h.split(":", 1)[1].strip() for h in _strings(http.get("headers"))
                              if h.lower().startswith("user-agent:")), "")
                host = re.sub(r"^[a-z]+://", "", url, flags=re.I).split("/", 1)[0].rsplit("@", 1)[-1].split(":", 1)[0]
                http_requests.append({"pid": pid, "process": "", "method": _text(http.get("method"), 16), "status": "",
                                      "ip": ip, "port": port, "url": url, "domain": host, "country": "",
                                      "contentType": "", "size": "", "reputation": "", "userAgent": agent[:300]})
    if not dynamics:
        # Overview only: the destinations are known, the process and port behind them are not.
        targets = _rows(overview.get("targets"))
        for block in [_dict(_dict(overview.get("sample")).get("iocs"))] + [_dict(t.get("iocs")) for t in targets]:
            for ip in _strings(block.get("ips")):
                if ip not in {c["ip"] for c in connections}:
                    connections.append({"ip": ip, "port": None, "pid": None, "process": "", "domain": "", "asn": "",
                                        "country": "", "reputation": ""})
            for domain in _strings(block.get("domains")):
                dns.setdefault(domain, [])
            for url in _strings(block.get("urls")):
                if url not in {r["url"] for r in http_requests}:
                    host = re.sub(r"^[a-z]+://", "", url, flags=re.I).split("/", 1)[0].split(":", 1)[0]
                    http_requests.append({"pid": None, "process": "", "method": "", "status": "", "ip": "",
                                          "port": None, "url": url, "domain": host, "country": "", "contentType": "",
                                          "size": "", "reputation": "", "userAgent": ""})
    return {"connections": connections[:MAX_ROWS], "httpRequests": http_requests[:MAX_ROWS],
            "dnsRequests": [{"domain": d, "ips": ips, "reputation": ""} for d, ips in list(dns.items())[:MAX_ROWS]],
            "alerts": []}


def _processes(dynamics: list[dict]) -> list[dict]:
    rows = []
    for dynamic in dynamics:
        for proc in _rows(dynamic.get("processes")):
            cmd = proc.get("cmd")
            image = _text(proc.get("image"))
            rows.append({"uuid": "", "pid": proc.get("pid") if isinstance(proc.get("pid"), int) else 0,
                         "ppid": proc.get("ppid") if isinstance(proc.get("ppid"), int) else None,
                         "parentName": "", "name": _basename(image), "path": image,
                         "cmd": " ".join(_strings(cmd)) if isinstance(cmd, list) else _text(cmd, 4000),
                         "indicators": ["original sample"] if proc.get("orig") is True else [],
                         "modules": [], "moduleCount": 0, "isInjected": None,
                         "scores": {"verdict": {"threatLevel": 0}}})
    return rows[:2000]


def _dropped(dynamics: list[dict]) -> list[dict]:
    rows = []
    for dynamic in dynamics:
        for dump in _rows(dynamic.get("dumped")):
            path = _text(dump.get("path"))
            if not path or not dump.get("sha256"):
                continue  # memory dumps and extracted configs have no on-disk path
            rows.append({"filename": path, "pid": dump.get("pid") if isinstance(dump.get("pid"), int) else None,
                         "process": "",
                         "hashes": {"md5": _text(dump.get("md5"), 32), "sha256": _text(dump.get("sha256"), 64)},
                         "type": _text(dump.get("kind"), 40), "timestamp": None})
    return rows[:MAX_ROWS]


def _configs(overview: dict, dynamics: list[dict]) -> list[str]:
    rows = []
    for source in [overview] + dynamics:
        for item in _rows(source.get("extracted")):
            config, note = _dict(item.get("config")), _dict(item.get("ransom_note"))
            if config:
                keep = {k: config[k] for k in ("rule", "c2", "version", "botnet", "campaign", "mutex", "dns", "wallet",
                                               "command_lines", "listen_addr", "listen_port") if config.get(k)}
                rows.append({"family": _text(config.get("family"), 80), "pid": None, "config": keep})
            if note:
                keep = {k: note[k] for k in ("wallets", "emails", "urls", "contact") if note.get(k)}
                keep["ransom_note"] = _text(note.get("note"), 600)
                rows.append({"family": _text(note.get("family"), 80), "pid": None, "config": keep})
    unique = list(dict.fromkeys(json.dumps(row, ensure_ascii=False, sort_keys=True)[:4000] for row in rows))
    return unique[:10]


def triage_to_report(overview: dict, dynamics: list[dict] | None = None) -> dict:
    """Build the pipeline's report from a Triage overview and its dynamic task reports."""
    if not is_triage_report(overview):
        raise TriageReportError("Không phải báo cáo overview của Triage (thiếu sample.sha256)")
    dynamics = [d for d in (dynamics or []) if isinstance(d, dict)][:4]
    sample, analysis = _dict(overview.get("sample")), _dict(overview.get("analysis"))
    tasks = _rows(overview.get("tasks"))
    sample_id = _text(sample.get("id"), 40)
    task_tags = [tag for task in tasks for tag in _strings(task.get("tags"))]
    tags = list(dict.fromkeys(_strings(analysis.get("tags")) + task_tags))
    families = _strings(analysis.get("family")) or [
        family for target in _rows(overview.get("targets")) for family in _strings(target.get("family"))]
    families = families or [t.split(":", 1)[1] for t in tags if t.startswith("family:")]
    score = analysis.get("score") if isinstance(analysis.get("score"), int) else sample.get("score")
    level = _threat_level(score)
    signatures = _signatures(overview, dynamics)

    mitre = {}
    for signature in signatures:
        for technique in signature["ttp"]:
            mitre.setdefault(technique, {"id": technique, "name": "", "tactic": "", "origin": "source_report",
                                         "evidence_text": signature["name"]})
    behaviors = [{"severity": "malicious" if s["score"] >= 8 else "suspicious" if s["score"] >= 5 else "info",
                  "name": s["name"], "description": s["desc"],
                  "processes": [{"name": "", "pid": pid} for pid in s["pids"][:50]]} for s in signatures]
    platform = next((_text(t.get("platform"), 60) for t in tasks if t.get("platform")), "Unknown OS")

    content = {
        "mainObject": {"filename": _text(sample.get("target"), 300) or "unknown",
                       "size": sample.get("size") if isinstance(sample.get("size"), int) else 0,
                       "hashes": {k: _text(sample.get(k), 64).lower() for k in ("md5", "sha1", "sha256")},
                       "type": _text(sample.get("filetype"), 200), "mime": ""},
        "scores": {"verdict": {"threatLevel": level,
                               "threat": ["No threats detected", "Suspicious activity", "Malicious activity"][level]},
                   "specs": {"knownThreat": families[0] if families else ""}},
        "mitre": list(mitre.values()),
        "network": _network(overview, dynamics),
        "processes": _processes(dynamics),
        "dropped": _dropped(dynamics),
        "registry": [], "synchronization": [],
        "behaviors": behaviors,
        "threatClasses": [], "indicators": [],
        "malwareConfig": _configs(overview, dynamics),
    }
    return {"data": {"analysis": {
        "uuid": sample_id or "triage", "status": "done", "duration": 0, "tags": [t[:80] for t in tags][:60],
        "options": {"os": {"version": platform}},
        "sandbox": {"name": "Triage", "sample_id": sample_id, "score": score if isinstance(score, int) else None,
                    "url": f"https://tria.ge/{sample_id}" if SAMPLE_ID_RE.fullmatch(sample_id) else "",
                    "dynamic_reports": len(dynamics)},
    }, "content": content}}
