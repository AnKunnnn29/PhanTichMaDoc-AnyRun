from __future__ import annotations

import json
from io import StringIO

import pytest
from rich.console import Console

import reporter
from reporter import ReportExporter, TerminalReporter, build_html_report, build_malware_analysis

pytestmark = pytest.mark.unit


class TestMarkdownExport:
    def test_export_markdown_creates_file(self, sample_analysis_result, sample_playbook, temp_output_dir):
        path = ReportExporter(str(temp_output_dir)).export_markdown(sample_analysis_result, sample_playbook)

        assert path.exists()
        assert path.suffix == ".md"
        assert path.read_text(encoding="utf-8").startswith("# Báo Cáo Phản Ứng Sự Cố")

    def test_markdown_contains_required_sections(self, sample_analysis_result, sample_playbook, temp_output_dir):
        path = ReportExporter(str(temp_output_dir)).export_markdown(sample_analysis_result, sample_playbook)
        text = path.read_text(encoding="utf-8")

        assert "Emotet" in text
        assert "`CRITICAL`" in text
        assert "## 3. MITRE ATT&CK Techniques" in text
        assert "| T1566.001 | Spearphishing Attachment | Initial Access |" in text
        assert "## 6. Quy Trình Phản Ứng Sự Cố" in text
        assert "## 7. IOC Blocklist" in text

    def test_markdown_groups_actions_by_phase(self, sample_analysis_result, sample_playbook, temp_output_dir):
        path = ReportExporter(str(temp_output_dir)).export_markdown(sample_analysis_result, sample_playbook)
        text = path.read_text(encoding="utf-8")

        assert "### Xác định (Identification)" in text
        assert "### Ngăn chặn (Containment)" in text


class TestJSONExport:
    def test_export_json_creates_parseable_json(self, sample_analysis_result, sample_playbook, temp_output_dir):
        path = ReportExporter(str(temp_output_dir)).export_json(sample_analysis_result, sample_playbook)

        parsed = json.loads(path.read_text(encoding="utf-8"))

        assert parsed["task_uuid"] == "test-task-uuid"
        assert parsed["severity"] == "CRITICAL"
        assert parsed["malware_name"] == "Emotet"
        assert parsed["actions"]
        assert parsed["ioc_blocklist"]["domains"] == ["evil.example", "c2.example"]

    def test_export_json_round_trip_preserves_required_fields(
        self, sample_analysis_result, sample_playbook, temp_output_dir
    ):
        path = ReportExporter(str(temp_output_dir)).export_json(sample_analysis_result, sample_playbook)
        parsed = json.loads(path.read_text(encoding="utf-8"))

        for field in ["task_uuid", "severity", "actions", "ioc_blocklist"]:
            assert field in parsed


class TestHTMLPDFExport:
    def test_export_html_creates_self_contained_report(self, sample_analysis_result, sample_playbook, temp_output_dir):
        path = ReportExporter(str(temp_output_dir)).export_html(sample_analysis_result, sample_playbook)
        text = path.read_text(encoding="utf-8")

        assert path.exists()
        assert path.suffix == ".html"
        assert text.startswith("<!doctype html>")
        assert "Emotet" in text
        assert "IOC Blocklist" in text

    def test_export_pdf_creates_pdf_file(self, sample_analysis_result, sample_playbook, temp_output_dir):
        path = ReportExporter(str(temp_output_dir)).export_pdf(sample_analysis_result, sample_playbook)

        assert path.exists()
        assert path.suffix == ".pdf"
        assert path.read_bytes().startswith(b"%PDF")
        assert path.stat().st_size > 1000

    def test_build_html_report_escapes_untrusted_content(self):
        html = build_html_report(
            {
                "task_uuid": "task-1",
                "analysis_url": "https://app.any.run/tasks/task-1",
                "playbook": {
                    "malware_name": "<script>alert(1)</script>",
                    "severity": "HIGH",
                    "summary": "<b>malicious</b>",
                    "actions": [],
                    "ioc_blocklist": {},
                },
                "threat": {"mitre": [], "tags": []},
            }
        )

        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
        assert "&lt;b&gt;malicious&lt;/b&gt;" in html


class TestReportContent:
    def test_build_malware_analysis_includes_mitre_descriptions(self, sample_analysis_result):
        analysis = build_malware_analysis(sample_analysis_result)
        behavior = "\n".join(analysis["behavior"])

        assert "MITRE T1566" in behavior
        assert "process injection" in behavior.lower()
        assert "C2" in behavior

    def test_build_malware_analysis_has_fallback_for_sparse_result(self, sample_analysis_result):
        sample_analysis_result.threat_info.mitre_techniques = []
        sample_analysis_result.network.ip_addresses = []
        sample_analysis_result.network.domains = []
        sample_analysis_result.network.urls = []
        sample_analysis_result.processes.injected_processes = []
        sample_analysis_result.processes.registry_keys = []

        analysis = build_malware_analysis(sample_analysis_result)

        assert "chưa đủ tín hiệu" in analysis["behavior"][0]
        assert analysis["affected_files"]
        assert analysis["origin"]

    def test_exporter_raises_when_output_path_is_file(self, tmp_path, sample_analysis_result, sample_playbook):
        output_file = tmp_path / "not-a-directory"
        output_file.write_text("occupied", encoding="utf-8")

        with pytest.raises(FileExistsError):
            ReportExporter(str(output_file))

    def test_uniq_deduplicates_values_and_dicts(self):
        values = ["a", "a", {"b": 1}, {"b": 1}, ""]

        assert reporter._uniq(values) == ["a", {"b": 1}]


class TestTerminalReporter:
    def test_print_analysis_renders_key_sections(self, monkeypatch, sample_analysis_result):
        stream = StringIO()
        monkeypatch.setattr(reporter, "console", Console(file=stream, width=120, force_terminal=False))

        TerminalReporter().print_analysis(sample_analysis_result)

        output = stream.getvalue()
        assert "KẾT QUẢ PHÂN TÍCH ANY.RUN" in output
        assert "Emotet" in output
        assert "MITRE ATT&CK Techniques" in output

    def test_print_playbook_renders_actions_and_iocs(self, monkeypatch, sample_playbook):
        stream = StringIO()
        monkeypatch.setattr(reporter, "console", Console(file=stream, width=120, force_terminal=False))

        TerminalReporter().print_playbook(sample_playbook)

        output = stream.getvalue()
        assert "QUY TRÌNH PHẢN ỨNG SỰ CỐ" in output
        assert "IOC Blocklist Tổng hợp" in output
        assert "Block C2" in output
