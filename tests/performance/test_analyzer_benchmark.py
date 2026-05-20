from __future__ import annotations

import copy

import pytest

from analyzer import MalwareAnalyzer

pytestmark = [pytest.mark.performance, pytest.mark.slow]


def test_parse_small_report_performance(benchmark, emotet_report, emotet_ioc):
    analyzer = MalwareAnalyzer()

    result = benchmark(analyzer.parse_report, emotet_report, emotet_ioc)

    assert result.threat_info.threat_name == "Emotet"


def test_parse_large_report_completes_within_budget(benchmark, emotet_report, emotet_ioc):
    report = copy.deepcopy(emotet_report)
    content = report["data"]["content"]
    content["processes"] = content["processes"] * 300
    content["network"]["connections"] = content["network"]["connections"] * 300
    content["network"]["httpRequests"] = content["network"]["httpRequests"] * 300

    result = benchmark(MalwareAnalyzer().parse_report, report, emotet_ioc)

    assert result.threat_info.threat_name == "Emotet"
    assert benchmark.stats["mean"] < 2.0


def test_parse_complex_mitre_report_performance(benchmark, emotet_report, emotet_ioc):
    report = copy.deepcopy(emotet_report)
    report["data"]["content"]["mitre"] = [
        {"id": f"T{1000 + idx}", "name": f"Technique {idx}", "tactic": "Discovery"} for idx in range(100)
    ]

    result = benchmark(MalwareAnalyzer().parse_report, report, emotet_ioc)

    assert len(result.threat_info.mitre_techniques) == 100
