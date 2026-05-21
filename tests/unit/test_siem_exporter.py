from __future__ import annotations

import csv
from io import StringIO

import pytest

from siem_exporter import build_elastic_kql, build_ioc_csv, build_siem_export, build_sigma_rule, build_splunk_query

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


def test_build_sigma_rule_contains_detection_sections(siem_payload):
    rule = build_sigma_rule(siem_payload)

    assert "title: AnyRun IR IOC Hunt - Emotet" in rule
    assert "selection_ip" in rule
    assert "selection_domain" in rule
    assert "selection_hash" in rule
    assert "level: critical" in rule


def test_build_ioc_csv_is_parseable(siem_payload):
    text = build_ioc_csv(siem_payload)
    rows = list(csv.DictReader(StringIO(text)))

    assert rows[0]["type"] == "ip_addresses"
    assert rows[0]["value"] == "192.0.2.10"
    assert {row["value"] for row in rows} >= {"evil.example", "sha256-test", "payload.dll"}


@pytest.mark.parametrize("fmt", ["splunk", "elastic", "sigma", "csv"])
def test_build_siem_export_dispatches_all_supported_formats(siem_payload, fmt):
    assert build_siem_export(siem_payload, fmt)


def test_build_siem_export_rejects_unknown_format(siem_payload):
    with pytest.raises(ValueError):
        build_siem_export(siem_payload, "xml")
