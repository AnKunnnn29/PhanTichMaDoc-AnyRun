from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

pytestmark = pytest.mark.integration


def _run_cli(project_root, *args):
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        [sys.executable, "main.py", *args],
        cwd=project_root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        env=env,
    )


class TestCLIDemoMode:
    def test_demo_mode_completes_and_exports_reports(self, project_root, tmp_path):
        result = _run_cli(project_root, "--demo", "--output", str(tmp_path))

        assert result.returncode == 0
        assert "Xuất báo cáo thành công" in result.stdout
        assert list(tmp_path.glob("*.md"))
        assert list(tmp_path.glob("*.json"))

    def test_demo_no_export_creates_no_report_files(self, project_root, tmp_path):
        result = _run_cli(project_root, "--demo", "--no-export", "--output", str(tmp_path))

        assert result.returncode == 0
        assert not list(tmp_path.glob("*.md"))
        assert not list(tmp_path.glob("*.json"))


class TestCLIReportImport:
    def test_report_json_import_with_valid_file_completes(self, project_root, tmp_path, emotet_report):
        report_path = tmp_path / "emotet_report.json"
        output_dir = tmp_path / "out"
        report_path.write_text(json.dumps(emotet_report), encoding="utf-8")

        result = _run_cli(project_root, "--report-json", str(report_path), "--output", str(output_dir))

        assert result.returncode == 0
        assert list(output_dir.glob("*.md"))
        assert list(output_dir.glob("*.json"))

    def test_report_json_import_with_missing_file_fails(self, project_root, tmp_path):
        result = _run_cli(project_root, "--report-json", str(tmp_path / "missing.json"))

        assert result.returncode == 1
        assert "Không đọc được JSON import" in result.stdout
