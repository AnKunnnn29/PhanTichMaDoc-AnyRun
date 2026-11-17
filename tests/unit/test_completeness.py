from __future__ import annotations

import copy

import pytest

from ir_workspace.analysis.analysis_pipeline import research_markdown, run_pipeline
from ir_workspace.analysis.completeness import data_completeness
from ir_workspace.reporting.reporter import _report_payload

pytestmark = pytest.mark.unit


def test_full_report_has_no_gap(emotet_report):
    result = data_completeness(emotet_report)

    assert result["complete"] and result["missing"] == [] and result["note"] == ""
    assert {s["id"] for s in result["sections"]} == {"processes", "network", "files", "registry", "behaviors"}


def test_empty_sections_are_named_and_not_read_as_no_behaviour(emotet_report):
    report = copy.deepcopy(emotet_report)
    report["data"]["content"]["registry"] = []
    report["data"]["content"]["network"] = {"connections": [], "httpRequests": [], "dnsRequests": []}

    result = data_completeness(report)

    assert result["missing"] == ["Hoạt động mạng", "Registry"] and not result["complete"]
    assert "hoạt động mạng, registry" in result["note"]
    assert "không có nghĩa là mẫu không có hành vi" in result["note"]


def test_malformed_sections_count_as_missing():
    result = data_completeness({"data": {"content": {"processes": "text", "network": ["x"], "dropped": None}}})

    assert len(result["missing"]) == 5


def test_gap_is_carried_in_the_payload_and_the_export(emotet_report, emotet_ioc):
    report = copy.deepcopy(emotet_report)
    report["data"]["content"]["registry"] = []

    payload = _report_payload(*run_pipeline(report, emotet_ioc, source="test"))

    assert payload["data_completeness"]["missing"] == ["Registry"]
    assert "Báo cáo nguồn không có dữ liệu về: registry." in research_markdown(payload)
    complete = _report_payload(*run_pipeline(emotet_report, emotet_ioc, source="test"))
    assert "Báo cáo nguồn không có dữ liệu" not in research_markdown(complete)
