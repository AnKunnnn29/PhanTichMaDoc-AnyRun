from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import datetime, timezone
from typing import Any

SIEM_FORMATS = {"splunk", "elastic", "sentinel", "sigma", "suricata", "stix", "csv"}
SIEM_EXTENSIONS = {
    "splunk": "spl",
    "elastic": "kql",
    "sentinel": "kql",
    "sigma": "yml",
    "suricata": "rules",
    "stix": "json",
    "csv": "csv",
}


def _clean_values(values: list[Any]) -> list[str]:
    seen = set()
    cleaned = []
    for value in values or []:
        text = str(value or "").strip()
        if text and text not in seen:
            seen.add(text)
            cleaned.append(text)
    return cleaned


def _blocklist(data: dict[str, Any]) -> dict[str, list[str]]:
    playbook = data.get("playbook", {}) or {}
    blocklist = playbook.get("ioc_blocklist", {}) or {}
    network = data.get("network", {}) or {}
    return {
        "ip_addresses": _clean_values(blocklist.get("ip_addresses", []) or network.get("ips", [])),
        "domains": _clean_values(blocklist.get("domains", []) or network.get("domains", [])),
        "urls": _clean_values(blocklist.get("urls", []) or network.get("urls", [])),
        "file_hashes": _clean_values(blocklist.get("file_hashes", [])),
        "filenames": _clean_values(blocklist.get("filenames", [])),
    }


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _single_quote(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _splunk_in(field: str, values: list[str]) -> str:
    return f"{field} IN ({', '.join(_quote(value) for value in values)})"


def build_splunk_query(data: dict[str, Any]) -> str:
    iocs = _blocklist(data)
    clauses = []
    if iocs["ip_addresses"]:
        clauses.extend(
            [
                _splunk_in("src_ip", iocs["ip_addresses"]),
                _splunk_in("dest_ip", iocs["ip_addresses"]),
                _splunk_in("remote_ip", iocs["ip_addresses"]),
            ]
        )
    if iocs["domains"]:
        clauses.extend(
            [
                _splunk_in("query", iocs["domains"]),
                _splunk_in("url_domain", iocs["domains"]),
                _splunk_in("dest_host", iocs["domains"]),
            ]
        )
    if iocs["urls"]:
        clauses.append(_splunk_in("url", iocs["urls"]))
    if iocs["file_hashes"]:
        clauses.extend(
            [
                _splunk_in("file_hash", iocs["file_hashes"]),
                _splunk_in("sha256", iocs["file_hashes"]),
                _splunk_in("Hashes", iocs["file_hashes"]),
            ]
        )
    if iocs["filenames"]:
        clauses.extend(
            [
                _splunk_in("file_name", iocs["filenames"]),
                _splunk_in("process_name", iocs["filenames"]),
            ]
        )

    if not clauses:
        return 'search index=* "AnyRun IR Tool" | head 0'

    malware = data.get("playbook", {}).get("malware_name", "Unknown")
    severity = data.get("playbook", {}).get("severity", "UNKNOWN")
    query = "search index=* (" + " OR ".join(clauses) + ")"
    return "\n".join(
        [
            query,
            f"| eval ir_malware={_quote(malware)}, ir_severity={_quote(severity)}",
            "| table _time host sourcetype src_ip dest_ip remote_ip query url_domain url "
            "file_hash sha256 file_name process_name ir_malware ir_severity",
        ]
    )


def _kql_terms(field: str, values: list[str]) -> str:
    return f"{field}: ({' or '.join(_quote(value) for value in values)})"


def build_elastic_kql(data: dict[str, Any]) -> str:
    iocs = _blocklist(data)
    clauses = []
    if iocs["ip_addresses"]:
        clauses.extend(
            [
                _kql_terms("source.ip", iocs["ip_addresses"]),
                _kql_terms("destination.ip", iocs["ip_addresses"]),
                _kql_terms("client.ip", iocs["ip_addresses"]),
                _kql_terms("server.ip", iocs["ip_addresses"]),
            ]
        )
    if iocs["domains"]:
        clauses.extend(
            [
                _kql_terms("dns.question.name", iocs["domains"]),
                _kql_terms("url.domain", iocs["domains"]),
                _kql_terms("destination.domain", iocs["domains"]),
            ]
        )
    if iocs["urls"]:
        clauses.append(_kql_terms("url.full", iocs["urls"]))
    if iocs["file_hashes"]:
        clauses.extend(
            [
                _kql_terms("file.hash.sha256", iocs["file_hashes"]),
                _kql_terms("process.hash.sha256", iocs["file_hashes"]),
            ]
        )
    if iocs["filenames"]:
        clauses.extend(
            [
                _kql_terms("file.name", iocs["filenames"]),
                _kql_terms("process.name", iocs["filenames"]),
            ]
        )
    return " or\n".join(clauses) if clauses else 'message: "AnyRun IR Tool" and not *'


def _kql_dynamic(values: list[str]) -> str:
    return "dynamic([" + ", ".join(_quote(value) for value in values) + "])"


def build_sentinel_kql(data: dict[str, Any]) -> str:
    iocs = _blocklist(data)
    malware = data.get("playbook", {}).get("malware_name", "Unknown")
    severity = data.get("playbook", {}).get("severity", "UNKNOWN")
    ip_values = _kql_dynamic(iocs["ip_addresses"])
    domain_values = _kql_dynamic(iocs["domains"])
    url_values = _kql_dynamic(iocs["urls"])
    hash_values = _kql_dynamic(iocs["file_hashes"])
    file_values = _kql_dynamic(iocs["filenames"])

    return "\n".join(
        [
            f"// AnyRun IR IOC hunt - {malware} ({severity})",
            f"let ir_ips = {ip_values};",
            f"let ir_domains = {domain_values};",
            f"let ir_urls = {url_values};",
            f"let ir_hashes = {hash_values};",
            f"let ir_files = {file_values};",
            "let network_hits = union isfuzzy=true",
            "  (DeviceNetworkEvents | where RemoteIP in (ir_ips) or RemoteUrl in (ir_domains) or RemoteUrl in (ir_urls) | project TimeGenerated, DeviceName, AccountName, Indicator=coalesce(RemoteUrl, RemoteIP), Source='DeviceNetworkEvents'),",
            "  (CommonSecurityLog | where DestinationIP in (ir_ips) or RequestURL in (ir_urls) or DestinationHostName in (ir_domains) | project TimeGenerated, DeviceName=Computer, AccountName=SourceUserName, Indicator=coalesce(RequestURL, DestinationHostName, DestinationIP), Source='CommonSecurityLog');",
            "let file_hits = DeviceFileEvents | where SHA256 in (ir_hashes) or FileName in (ir_files) | project TimeGenerated, DeviceName, AccountName, Indicator=coalesce(SHA256, FileName), Source='DeviceFileEvents';",
            "union network_hits, file_hits",
            "| summarize FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated), Sources=make_set(Source), Indicators=make_set(Indicator) by DeviceName, AccountName",
            "| order by LastSeen desc",
        ]
    )


def _yaml_list(values: list[str], indent: int = 6) -> list[str]:
    prefix = " " * indent + "- "
    return [prefix + _quote(value) for value in values]


def build_sigma_rule(data: dict[str, Any]) -> str:
    iocs = _blocklist(data)
    playbook = data.get("playbook", {}) or {}
    threat = data.get("threat", {}) or {}
    malware = playbook.get("malware_name") or threat.get("threat_name") or "Unknown Malware"
    severity = str(playbook.get("severity") or "medium").lower()
    level = "critical" if severity == "critical" else "high" if severity in {"high", "critical"} else "medium"
    rule_id = str(data.get("task_uuid") or "anyrun-ir-tool-prototype").replace(" ", "-")

    lines = [
        f"title: AnyRun IR IOC Hunt - {malware}",
        f"id: {rule_id}",
        "status: experimental",
        f"description: IOC hunt rule generated from AnyRun IR Tool for {malware}.",
        "author: AnyRun IR Tool",
        f"date: {datetime.now(timezone.utc).strftime('%Y/%m/%d')}",
        "logsource:",
        "  product: windows",
        "detection:",
    ]
    conditions = []
    if iocs["ip_addresses"]:
        conditions.append("selection_ip")
        lines.extend(["  selection_ip:", "    DestinationIp:"])
        lines.extend(_yaml_list(iocs["ip_addresses"]))
        lines.extend(["    SourceIp:"])
        lines.extend(_yaml_list(iocs["ip_addresses"]))
    if iocs["domains"]:
        conditions.append("selection_domain")
        lines.extend(["  selection_domain:", "    QueryName:"])
        lines.extend(_yaml_list(iocs["domains"]))
        lines.extend(["    DestinationHostname:"])
        lines.extend(_yaml_list(iocs["domains"]))
    if iocs["file_hashes"]:
        conditions.append("selection_hash")
        lines.extend(["  selection_hash:", "    Hashes|contains:"])
        lines.extend(_yaml_list(iocs["file_hashes"]))
    if iocs["filenames"]:
        conditions.append("selection_file")
        lines.extend(["  selection_file:", "    Image|endswith:"])
        lines.extend(_yaml_list(iocs["filenames"]))

    condition = " or ".join(conditions) if conditions else "false"
    lines.extend(
        [
            f"  condition: {condition}",
            f"level: {level}",
            "tags:",
            "  - attack.command_and_control",
            "  - attack.execution",
            "falsepositives:",
            "  - Internal testing traffic or reused benign infrastructure.",
        ]
    )
    return "\n".join(lines) + "\n"


def build_ioc_csv(data: dict[str, Any]) -> str:
    iocs = _blocklist(data)
    playbook = data.get("playbook", {}) or {}
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(["type", "value", "malware_name", "severity", "task_uuid", "analysis_url"])
    for ioc_type, values in iocs.items():
        for value in values:
            writer.writerow(
                [
                    ioc_type,
                    value,
                    playbook.get("malware_name", ""),
                    playbook.get("severity", ""),
                    data.get("task_uuid", ""),
                    data.get("analysis_url", ""),
                ]
            )
    return output.getvalue()


def _sid_base(data: dict[str, Any]) -> int:
    key = str(data.get("task_uuid") or data.get("analysis_url") or data.get("playbook", {}).get("malware_name") or "anyrun")
    return 9000000 + (uuid.uuid5(uuid.NAMESPACE_URL, key).int % 500000)


def _suricata_content(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace(";", "\\;")


def build_suricata_rules(data: dict[str, Any]) -> str:
    iocs = _blocklist(data)
    playbook = data.get("playbook", {}) or {}
    malware = playbook.get("malware_name", "Unknown")
    severity = playbook.get("severity", "UNKNOWN")
    sid = _sid_base(data)
    rev = 1
    rules = [
        f"# AnyRun IR Suricata rules - {malware} ({severity})",
        "# Review internally before deploying to production sensors.",
    ]

    for ip in iocs["ip_addresses"][:100]:
        rules.append(
            f'alert ip any any -> {ip} any (msg:"ANYRUN IR {malware} IP IOC {ip}"; '
            f"metadata:malware {malware}, severity {severity}; sid:{sid}; rev:{rev};)"
        )
        sid += 1
    for domain in iocs["domains"][:100]:
        escaped = _suricata_content(domain)
        rules.append(
            f'alert dns any any -> any any (msg:"ANYRUN IR {malware} DNS IOC {domain}"; '
            f'dns.query; content:"{escaped}"; nocase; '
            f"metadata:malware {malware}, severity {severity}; sid:{sid}; rev:{rev};)"
        )
        sid += 1
        rules.append(
            f'alert http any any -> any any (msg:"ANYRUN IR {malware} HTTP Host IOC {domain}"; '
            f'http.host; content:"{escaped}"; nocase; '
            f"metadata:malware {malware}, severity {severity}; sid:{sid}; rev:{rev};)"
        )
        sid += 1
    for url in iocs["urls"][:100]:
        escaped = _suricata_content(url)
        rules.append(
            f'alert http any any -> any any (msg:"ANYRUN IR {malware} URL IOC"; '
            f'http.uri; content:"{escaped}"; nocase; '
            f"metadata:malware {malware}, severity {severity}; sid:{sid}; rev:{rev};)"
        )
        sid += 1

    if len(rules) == 2:
        rules.append("# No network IOC available for Suricata rule generation.")
    return "\n".join(rules) + "\n"


def _stix_id(stix_type: str, key: str) -> str:
    return f"{stix_type}--{uuid.uuid5(uuid.NAMESPACE_URL, stix_type + ':' + key)}"


def _hash_pattern(value: str) -> str:
    algo = "SHA-256" if len(value) == 64 else "SHA-1" if len(value) == 40 else "MD5" if len(value) == 32 else "SHA-256"
    return f"[file:hashes.'{algo}' = {_single_quote(value)}]"


def build_stix_bundle(data: dict[str, Any]) -> str:
    iocs = _blocklist(data)
    playbook = data.get("playbook", {}) or {}
    malware = playbook.get("malware_name", "Unknown Malware")
    severity = playbook.get("severity", "UNKNOWN")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    identity_id = _stix_id("identity", "AnyRun IR Tool")
    objects: list[dict[str, Any]] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now,
            "modified": now,
            "name": "AnyRun IR Tool",
            "identity_class": "system",
        }
    ]

    def add_indicator(kind: str, value: str, pattern: str) -> None:
        name = f"{malware} {kind} IOC"
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": _stix_id("indicator", kind + ":" + value),
                "created": now,
                "modified": now,
                "created_by_ref": identity_id,
                "name": name,
                "description": f"IOC extracted from Any.Run IR workflow. Severity: {severity}.",
                "indicator_types": ["malicious-activity"],
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": now,
                "labels": ["anyrun-ir", str(severity).lower(), str(malware).lower().replace(" ", "-")],
                "external_references": [
                    {"source_name": "ANY.RUN", "url": data.get("analysis_url", "")}
                ],
            }
        )

    for ip in iocs["ip_addresses"]:
        add_indicator("ip", ip, f"[ipv4-addr:value = {_single_quote(ip)}]")
    for domain in iocs["domains"]:
        add_indicator("domain", domain, f"[domain-name:value = {_single_quote(domain)}]")
    for url in iocs["urls"]:
        add_indicator("url", url, f"[url:value = {_single_quote(url)}]")
    for file_hash in iocs["file_hashes"]:
        add_indicator("file-hash", file_hash, _hash_pattern(file_hash))
    for filename in iocs["filenames"]:
        add_indicator("filename", filename, f"[file:name = {_single_quote(filename)}]")

    bundle = {
        "type": "bundle",
        "id": _stix_id("bundle", str(data.get("task_uuid") or now)),
        "objects": objects,
    }
    return json.dumps(bundle, ensure_ascii=False, indent=2) + "\n"


def build_siem_export(data: dict[str, Any], fmt: str) -> str:
    if fmt == "splunk":
        return build_splunk_query(data)
    if fmt == "elastic":
        return build_elastic_kql(data)
    if fmt == "sentinel":
        return build_sentinel_kql(data)
    if fmt == "sigma":
        return build_sigma_rule(data)
    if fmt == "suricata":
        return build_suricata_rules(data)
    if fmt == "stix":
        return build_stix_bundle(data)
    if fmt == "csv":
        return build_ioc_csv(data)
    raise ValueError(f"Unsupported SIEM export format: {fmt}")
