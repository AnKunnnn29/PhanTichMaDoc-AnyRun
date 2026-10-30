"""Source-bound observables. References are observations, never proof of maliciousness."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from urllib.parse import urlsplit, urlunsplit

PIPELINE_VERSION = "evidence-agent-2.0"


def digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False,
                                     separators=(",", ":")).encode("utf-8")).hexdigest()


def normalize(kind: str, value: str) -> tuple[str, bool]:
    value = str(value).strip()
    if not value or len(value) > 8192 or any(ord(c) < 32 for c in value):
        return value, False
    if kind == "ip":
        try:
            return str(ipaddress.ip_address(value)), True
        except ValueError:
            return value, False
    if kind in {"md5", "sha1", "sha256"}:
        return value.lower(), bool(re.fullmatch(r"[a-fA-F0-9]{%d}" % {"md5": 32, "sha1": 40, "sha256": 64}[kind], value))
    if kind == "domain":
        value = value.rstrip(".").lower()
        try:
            value = value.encode("idna").decode("ascii")
        except UnicodeError:
            return value, False
        return value, bool(re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", value))
    if kind == "url":
        try:
            parts = urlsplit(value)
            if parts.scheme.lower() not in {"http", "https"} or not parts.hostname or parts.username:
                return value, False
            return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path, parts.query, parts.fragment)), True
        except ValueError:
            return value, False
    if kind == "mitre":
        return value.upper(), bool(re.fullmatch(r"T\d{4}(?:\.\d{3})?", value.upper()))
    return value, True


def collect_evidence(report: dict, iocs) -> dict:
    sources = {"report": report, "ioc": iocs}
    hashes = {key: digest(value) for key, value in sources.items()}
    records, observables, index = [], [], {}
    content = report["data"]["content"]
    markdown = report.get("import_metadata", {}).get("original_text", "")

    def add(kind, value, path, source="report", context=None, observable=True):
        if not isinstance(value, (str, int)) or isinstance(value, bool) or not str(value).strip():
            return
        raw = str(value)
        normalized, valid = normalize(kind, raw)
        eid = "ev-" + digest([hashes[source], path, raw])[:20]
        entry = {"id": eid, "type": kind, "value": raw, "source_id": source,
                 "source_sha256": hashes[source], "source_path": path, "context": context or {},
                 "observation": "reported" if kind == "mitre" else "observed"}
        if markdown:
            entry["observation"] = "reported"  # text export is not an event log
            entry["source_lines"] = [n for n, line in enumerate(markdown.splitlines(), 1) if raw.lower() in line.lower()][:20]
        records.append(entry)
        if not observable:
            # Behaviour signatures, IDS alerts and configs are evidence, not indicators to block.
            return
        key = (kind, normalized.casefold() if kind in {"file", "registry"} else normalized)
        if key not in index:
            observable = {"id": "ioc-" + digest(key)[:20], "type": kind, "value": normalized,
                          "valid": valid, "evidence_ids": [], "role": "unclassified"}
            index[key] = observable
            observables.append(observable)
        index[key]["evidence_ids"].append(eid)

    main = content.get("mainObject") or {}
    add("file", main.get("filename"), "/data/content/mainObject/filename")
    for algo in ("md5", "sha1", "sha256"):
        add(algo, (main.get("hashes") or {}).get(algo), "/data/content/mainObject/hashes/" + algo)
    network = content.get("network") or {}
    for collection, fields in {"connections": {"ip": "ip"}, "httpRequests": {"url": "url", "domain": "domain", "ip": "ip"},
                               "dnsRequests": {"domain": "domain"}}.items():
        for n, row in enumerate(network.get(collection) or []):
            for field, kind in fields.items():
                add(kind, row.get(field), f"/data/content/network/{collection}/{n}/{field}", context=row)
    for n, row in enumerate(network.get("dnsRequests") or []):
        for i, ip in enumerate(row.get("ips") or []):
            add("ip", ip, f"/data/content/network/dnsRequests/{n}/ips/{i}",
                context={"domain": row.get("domain", ""), "relation": "dns_answer", "reputation": row.get("reputation", "")})
    for n, row in enumerate(network.get("alerts") or []):
        add("alert", row.get("message"), f"/data/content/network/alerts/{n}/message", context=row, observable=False)
    for n, row in enumerate(content.get("behaviors") or []):
        add("behavior", row.get("name"), f"/data/content/behaviors/{n}/name", context=row, observable=False)
    for n, value in enumerate(content.get("malwareConfig") or []):
        add("malware_config", value, f"/data/content/malwareConfig/{n}", observable=False)
    for n, relation in enumerate(content.get("processRelations") or []):
        add("process_relation", relation.get("edge"), f"/data/content/processRelations/{n}/edge",
            context=relation, observable=False)
    static = content.get("staticProfile") or {}
    for n, row in enumerate(static.get("metadata") or []):
        add("pe_metadata", row.get("value"), f"/data/content/staticProfile/metadata/{n}/value", context=row, observable=False)
    for n, row in enumerate(static.get("trid") or []):
        add("file_type", row.get("value"), f"/data/content/staticProfile/trid/{n}/value", context=row, observable=False)
    for collection, field, kind in [("processes", "name", "process"), ("dropped", "filename", "file"),
                                    ("registry", "key", "registry"), ("synchronization", "name", "mutex"),
                                    ("mitre", "id", "mitre")]:
        for n, row in enumerate(content.get(collection) or []):
            add(kind, row.get(field), f"/data/content/{collection}/{n}/{field}", context=row)
            if collection == "processes":
                for m, module in enumerate(row.get("modules") or []):
                    add("module", module, f"/data/content/processes/{n}/modules/{m}",
                        context={"pid": row.get("pid"), "processUuid": row.get("uuid"), "process": row.get("name")}, observable=False)
            if collection == "dropped":
                for algo in ("md5", "sha1", "sha256"):
                    add(algo, (row.get("hashes") or {}).get(algo), f"/data/content/dropped/{n}/hashes/{algo}", context=row)
    items = iocs if isinstance(iocs, list) else iocs.get("data", iocs.get("iocs", []))
    prefix = "" if isinstance(iocs, list) else "/data" if "data" in iocs else "/iocs"
    for n, row in enumerate(items or []):
        kind = str(row.get("type", "")).lower()
        kind = {"filename": "file", "filepath": "file", "hostname": "domain"}.get(kind, kind)
        if kind in {"ip", "domain", "url", "md5", "sha1", "sha256", "file", "registry", "process", "mutex"}:
            add(kind, row.get("value"), f"{prefix}/{n}/value", "ioc")
    return {"schema_version": "1.0", "sources": [
        {"id": key, "sha256": hashes[key], "content": value} for key, value in sources.items()],
        "evidence": records, "observables": observables}


def resolve_pointer(document, pointer: str):
    value = document
    for key in pointer.strip("/").split("/"):
        key = key.replace("~1", "/").replace("~0", "~")
        value = value[int(key)] if isinstance(value, list) else value[key]
    return value


def validate_bundle(bundle: dict) -> None:
    sources = {s["id"]: s for s in bundle["sources"]}
    ids = set()
    for source in sources.values():
        if digest(source["content"]) != source["sha256"]:
            raise ValueError("Source hash mismatch")
    for entry in bundle["evidence"]:
        source = sources[entry["source_id"]]
        if entry["id"] in ids or entry["source_sha256"] != source["sha256"]:
            raise ValueError("Invalid evidence identity")
        if str(resolve_pointer(source["content"], entry["source_path"])) != entry["value"]:
            raise ValueError("Evidence does not match source")
        ids.add(entry["id"])
    for item in bundle["observables"]:
        if not item["evidence_ids"] or not set(item["evidence_ids"]) <= ids:
            raise ValueError("Unbound observable")
