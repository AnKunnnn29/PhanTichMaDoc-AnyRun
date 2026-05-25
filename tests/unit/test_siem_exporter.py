from __future__ import annotations

import csv
import json
from io import StringIO

import pytest

from siem_exporter import (
    build_elastic_kql,
    build_ioc_csv,
    build_sentinel_kql,
    build_siem_export,
    build_sigma_rule,
    build_splunk_query,
    build_stix_bundle,
    build_suricata_rules,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def siem_payload():
    return {
        "task_uuid": "task-1",
        "analysis_url": "https://app.any.run/tasks/task-1",
        "network": {"ips": ["192.0.2.10"], "domains": ["evil.example"], "urls": ["http://evil.example/payload"]},
        "threat": {"threat_name": "Emotet"},
        "playbook": {
            "malware_name": "Emotet",
            "severity": "CRITICAL",
            "ioc_blocklist": {
                "ip_addresses": ["192.0.2.10"],
                "domains": ["evil.example"],
                "urls": ["http://evil.example/payload"],
                "file_hashes": ["sha256-test"],
                "filenames": ["payload.dll"],
            },
        },
    }


def test_build_splunk_query_contains_common_ioc_fields(siem_payload):
    query = build_splunk_query(siem_payload)

    assert "src_ip IN" in query
    assert "dest_ip IN" in query
    assert "url_domain IN" in query
    assert '"192.0.2.10"' in query
    assert "ir_malware" in query


def test_build_elastic_kql_contains_ecs_fields(siem_payload):
    query = build_elastic_kql(siem_payload)

    assert "source.ip" in query
    assert "destination.ip" in query
    assert "dns.question.name" in query
    assert '"evil.example"' in query


def test_build_sentinel_kql_contains_m365_tables(siem_payload):
    query = build_sentinel_kql(siem_payload)

    assert "DeviceNetworkEvents" in query
    assert "CommonSecurityLog" in query
    assert "DeviceFileEvents" in query
    assert '"evil.example"' in query


def test_build_sigma_rule_contains_detection_sections(siem_payload):
    rule = build_sigma_rule(siem_payload)

    assert "title: AnyRun IR IOC Hunt - Emotet" in rule
    assert "selection_ip" in rule
    assert "selection_domain" in rule
    assert "selection_hash" in rule
    assert "level: critical" in rule


def test_build_suricata_rules_contains_network_iocs(siem_payload):
    rules = build_suricata_rules(siem_payload)

    assert "alert ip" in rules
    assert "alert dns" in rules
    assert "192.0.2.10" in rules
    assert "evil.example" in rules


def test_build_stix_bundle_contains_indicator_objects(siem_payload):
    bundle = json.loads(build_stix_bundle(siem_payload))

    assert bundle["type"] == "bundle"
    indicator_patterns = [obj.get("pattern", "") for obj in bundle["objects"] if obj["type"] == "indicator"]
    assert any("ipv4-addr:value" in pattern for pattern in indicator_patterns)
    assert any("domain-name:value" in pattern for pattern in indicator_patterns)
    assert any("file:hashes" in pattern for pattern in indicator_patterns)


def test_build_ioc_csv_is_parseable(siem_payload):
    text = build_ioc_csv(siem_payload)
    rows = list(csv.DictReader(StringIO(text)))

    assert rows[0]["type"] == "ip_addresses"
    assert rows[0]["value"] == "192.0.2.10"
    assert {row["value"] for row in rows} >= {"evil.example", "sha256-test", "payload.dll"}


@pytest.mark.parametrize("fmt", ["splunk", "elastic", "sentinel", "sigma", "suricata", "stix", "csv"])
def test_build_siem_export_dispatches_all_supported_formats(siem_payload, fmt):
    assert build_siem_export(siem_payload, fmt)


def test_build_siem_export_rejects_unknown_format(siem_payload):
    with pytest.raises(ValueError):
        build_siem_export(siem_payload, "xml")
