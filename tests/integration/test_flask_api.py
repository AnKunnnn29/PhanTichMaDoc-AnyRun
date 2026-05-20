from __future__ import annotations

import io
import json

import pytest

pytestmark = pytest.mark.integration


class TestDemoEndpoints:
    @pytest.mark.parametrize(
        ("malware", "expected_name"),
        [
            ("emotet", "Emotet"),
            ("wannacry", "WannaCry"),
            ("redline", "RedLine Stealer"),
        ],
    )
    def test_demo_endpoint_returns_analysis_payload(self, flask_test_client, malware, expected_name):
        response = flask_test_client.get(f"/api/demo/{malware}")

        assert response.status_code == 200
        payload = response.get_json()
        assert payload["ok"] is True
        assert payload["data"]["threat"]["threat_name"] == expected_name
        assert payload["data"]["playbook"]["actions"]


class TestAnalyzeEndpoint:
    def test_analyze_json_upload_with_valid_report(self, flask_test_client, emotet_report):
        response = flask_test_client.post(
            "/api/analyze/json",
            data={
                "force_analyze": "true",
                "report_file": (io.BytesIO(json.dumps(emotet_report).encode("utf-8")), "report.json"),
            },
            content_type="multipart/form-data",
        )

        assert response.status_code == 200
        payload = response.get_json()
        assert payload["ok"] is True
        assert payload["data"]["threat"]["threat_name"] == "Emotet"

    def test_analyze_json_upload_with_empty_file_returns_400(self, flask_test_client):
        response = flask_test_client.post(
            "/api/analyze/json",
            data={"report_file": (io.BytesIO(b""), "empty.json")},
            content_type="multipart/form-data",
        )

        assert response.status_code == 400
        assert response.get_json()["ok"] is False

    def test_analyze_json_upload_missing_file_returns_400(self, flask_test_client):
        response = flask_test_client.post("/api/analyze/json", data={}, content_type="multipart/form-data")

        assert response.status_code == 400
        assert "Thiếu file report" in response.get_json()["error"]

    def test_analyze_json_upload_rejects_unsupported_extension(self, flask_test_client):
        response = flask_test_client.post(
            "/api/analyze/json",
            data={"report_file": (io.BytesIO(b"{}"), "report.exe")},
            content_type="multipart/form-data",
        )

        assert response.status_code == 400
        payload = response.get_json()
        assert payload["ok"] is False
        assert payload["code"] == "bad_request"

    def test_analyze_endpoint_rejects_invalid_task_uuid(self, flask_test_client):
        response = flask_test_client.post(
            "/api/analyze",
            json={"api_key": "test-api-key", "task_id": "not-a-uuid"},
        )

        assert response.status_code == 400
        assert "UUID" in response.get_json()["error"]

    def test_submit_url_rejects_non_http_url(self, flask_test_client):
        response = flask_test_client.post(
            "/api/submit/url",
            json={"api_key": "test-api-key", "url": "ftp://example.test/payload"},
        )

        assert response.status_code == 400
        assert "URL" in response.get_json()["error"]

    def test_submit_file_rejects_unsupported_extension(self, flask_test_client):
        response = flask_test_client.post(
            "/api/submit/file",
            data={"api_key": "test-api-key", "file": (io.BytesIO(b"<?php ?>"), "shell.php")},
            content_type="multipart/form-data",
        )

        assert response.status_code == 400
        assert "không được hỗ trợ" in response.get_json()["error"]

    def test_rate_limit_returns_429(self, flask_test_client):
        for _ in range(30):
            response = flask_test_client.post("/api/export", json={"format": "json"})
            assert response.status_code == 400

        response = flask_test_client.post("/api/export", json={"format": "json"})

        assert response.status_code == 429
        assert response.get_json()["code"] == "rate_limited"


class TestExportAndHistoryEndpoints:
    def test_export_json_creates_report_file(self, flask_test_client):
        data = {"task_uuid": "task-1", "playbook": {"malware_name": "Emotet"}}

        response = flask_test_client.post("/api/export", json={"format": "json", "data": data})

        payload = response.get_json()
        assert response.status_code == 200
        assert payload["ok"] is True
        assert payload["path"].endswith(".json")

    def test_export_markdown_creates_report_file(self, flask_test_client):
        data = {
            "analysis_url": "https://app.any.run/tasks/task-1",
            "threat": {"verdict": "Malicious", "threat_level": 3, "mitre": []},
            "file": {"name": "sample.exe", "sha256": "hash", "type": "PE32"},
            "network": {"ips": ["192.0.2.1"], "domains": ["evil.example"], "urls": []},
            "processes": {"list": [], "injected": [], "dropped": [], "registry": []},
            "playbook": {
                "malware_name": "Emotet",
                "severity": "HIGH",
                "actions": [{"title": "Contain host", "description": "Isolate host.", "commands": []}],
                "ioc_blocklist": {"ip_addresses": ["192.0.2.1"], "domains": ["evil.example"]},
            },
        }

        response = flask_test_client.post("/api/export", json={"format": "markdown", "data": data})

        payload = response.get_json()
        assert response.status_code == 200
        assert payload["ok"] is True
        assert payload["path"].endswith(".md")

    def test_history_local_returns_list(self, flask_test_client):
        flask_test_client.get("/api/demo/emotet")

        response = flask_test_client.get("/api/history/local")

        assert response.status_code == 200
        payload = response.get_json()
        assert payload["ok"] is True
        assert isinstance(payload["items"], list)

    def test_export_without_data_returns_400(self, flask_test_client):
        response = flask_test_client.post("/api/export", json={"format": "json"})

        assert response.status_code == 400
        assert response.get_json()["ok"] is False

    def test_export_rejects_unsupported_format(self, flask_test_client):
        response = flask_test_client.post("/api/export", json={"format": "pdf", "data": {"task_uuid": "task-1"}})

        assert response.status_code == 400
        assert "Format export" in response.get_json()["error"]
