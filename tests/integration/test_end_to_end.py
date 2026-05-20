from __future__ import annotations

import json

import pytest

from analyzer import MalwareAnalyzer
from incident_response import IncidentResponseGenerator
from reporter import ReportExporter

pytestmark = pytest.mark.integration


@pytest.mark.parametrize(
    ("report_fixture", "ioc_fixture", "expected_name"),
    [
        ("emotet_report", "emotet_ioc", "Emotet"),
        ("wannacry_report", "wannacry_ioc", "WannaCry"),
        ("redline_report", "redline_ioc", "RedLine Stealer"),
    ],
)
def test_full_workflow_analyze_generate_export(request, tmp_path, report_fixture, ioc_fixture, expected_name):
    report = request.getfixturevalue(report_fixture)
    iocs = request.getfixturevalue(ioc_fixture)

    result = MalwareAnalyzer().parse_report(report, iocs)
    playbook = IncidentResponseGenerator().generate(result)
    exporter = ReportExporter(str(tmp_path))
    md_path = exporter.export_markdown(result, playbook)
    json_path = exporter.export_json(result, playbook)

    assert result.threat_info.threat_name == expected_name
    assert playbook.malware_name == expected_name
    assert md_path.exists()
    parsed = json.loads(json_path.read_text(encoding="utf-8"))
    assert parsed["malware_name"] == expected_name
