from __future__ import annotations

import pytest

from incident_response import IncidentResponseGenerator
from reporter import ReportExporter

pytestmark = [pytest.mark.performance, pytest.mark.slow]


def test_playbook_generation_performance(benchmark, sample_analysis_result):
    playbook = benchmark(IncidentResponseGenerator().generate, sample_analysis_result)

    assert playbook.actions
    assert benchmark.stats["mean"] < 0.5


def test_markdown_export_performance(benchmark, tmp_path, sample_analysis_result, sample_playbook):
    exporter = ReportExporter(str(tmp_path))

    path = benchmark(exporter.export_markdown, sample_analysis_result, sample_playbook)

    assert path.exists()
    assert benchmark.stats["mean"] < 1.0


def test_json_export_performance(benchmark, tmp_path, sample_analysis_result, sample_playbook):
    exporter = ReportExporter(str(tmp_path))

    path = benchmark(exporter.export_json, sample_analysis_result, sample_playbook)

    assert path.exists()
    assert benchmark.stats["mean"] < 0.5
