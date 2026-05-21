from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from typing import Any

SIEM_FORMATS = {"splunk", "elastic", "sigma", "csv"}
SIEM_EXTENSIONS = {
    "splunk": "spl",
    "elastic": "kql",
    "sigma": "yml",
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


def build_siem_export(data: dict[str, Any], fmt: str) -> str:
    if fmt == "splunk":
        return build_splunk_query(data)
    if fmt == "elastic":
        return build_elastic_kql(data)
    if fmt == "sigma":
        return build_sigma_rule(data)
    if fmt == "csv":
        return build_ioc_csv(data)
    raise ValueError(f"Unsupported SIEM export format: {fmt}")
