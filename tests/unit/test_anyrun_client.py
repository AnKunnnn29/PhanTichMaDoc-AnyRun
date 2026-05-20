from __future__ import annotations

from pathlib import Path

import pytest
import requests
import responses

from anyrun_client import (
    AnyRunAPIError,
    AnyRunAuthError,
    AnyRunClient,
    AnyRunNotFoundError,
    AnyRunRateLimitError,
)

pytestmark = pytest.mark.unit


class TestAnyRunClientInit:
    def test_valid_api_key_sets_headers(self):
        client = AnyRunClient("test-api-key", timeout=5)

        assert client.timeout == 5
        assert client.session.headers["Authorization"] == "API-Key test-api-key"
        assert client.session.headers["Accept"] == "application/json"

    @pytest.mark.parametrize("api_key", ["", None, "your_api_key_here"])
    def test_invalid_api_key_raises_auth_error(self, api_key):
        with pytest.raises(AnyRunAuthError, match="API key"):
            AnyRunClient(api_key)  # type: ignore[arg-type]


class TestAnyRunClientGetMethods:
    @responses.activate
    def test_get_task_report_returns_json(self, mock_anyrun_client, emotet_report):
        responses.add(
            responses.GET,
            "https://api.any.run/v1/report/550e8400-e29b-41d4-a716-446655440000/summary/json",
            json=emotet_report,
            status=200,
        )

        result = mock_anyrun_client.get_task_report("550e8400-e29b-41d4-a716-446655440000")

        assert result["data"]["analysis"]["uuid"] == emotet_report["data"]["analysis"]["uuid"]

    @responses.activate
    def test_get_task_iocs_returns_json(self, mock_anyrun_client, emotet_ioc):
        responses.add(
            responses.GET,
            "https://api.any.run/v1/report/550e8400-e29b-41d4-a716-446655440000/ioc/json",
            json=emotet_ioc,
            status=200,
        )

        result = mock_anyrun_client.get_task_iocs("550e8400-e29b-41d4-a716-446655440000")

        assert result["data"][0]["type"] == "ip"

    @responses.activate
    def test_get_history_sends_expected_params(self, mock_anyrun_client):
        responses.add(
            responses.GET,
            "https://api.any.run/v1/analysis",
            json={"data": {"tasks": [{"uuid": "550e8400-e29b-41d4-a716-446655440000"}]}},
            status=200,
        )

        result = mock_anyrun_client.get_history(team=True, skip=5, limit=10)

        request = responses.calls[0].request
        assert request.url.endswith("/analysis?team=true&skip=5&limit=10")
        assert result["data"]["tasks"][0]["uuid"] == "550e8400-e29b-41d4-a716-446655440000"


class TestAnyRunClientErrorHandling:
    @pytest.mark.parametrize(
        ("status", "error_type"),
        [
            (401, AnyRunAuthError),
            (403, AnyRunAuthError),
            (404, AnyRunNotFoundError),
            (429, AnyRunRateLimitError),
        ],
    )
    @responses.activate
    def test_http_error_status_maps_to_custom_error(self, mock_anyrun_client, status, error_type):
        responses.add(
            responses.GET,
            "https://api.any.run/v1/report/550e8400-e29b-41d4-a716-446655440000/summary/json",
            json={"status": "error"},
            status=status,
        )

        with pytest.raises(error_type):
            mock_anyrun_client.get_task_report("550e8400-e29b-41d4-a716-446655440000")

    @responses.activate
    def test_unexpected_http_status_raises_api_error(self, mock_anyrun_client):
        responses.add(
            responses.GET,
            "https://api.any.run/v1/report/550e8400-e29b-41d4-a716-446655440000/summary/json",
            body="server error",
            status=500,
        )

        with pytest.raises(AnyRunAPIError, match="HTTP 500"):
            mock_anyrun_client.get_task_report("550e8400-e29b-41d4-a716-446655440000")

    def test_connection_failure_raises_api_error(self, mock_anyrun_client, monkeypatch):
        def fail_request(*args, **kwargs):
            raise requests.ConnectionError("network down")

        monkeypatch.setattr(mock_anyrun_client.session, "request", fail_request)

        with pytest.raises(AnyRunAPIError, match="Any.Run API"):
            mock_anyrun_client.get_task_report("550e8400-e29b-41d4-a716-446655440000")

    def test_timeout_raises_api_error(self, mock_anyrun_client, monkeypatch):
        def fail_request(*args, **kwargs):
            raise requests.Timeout()

        monkeypatch.setattr(mock_anyrun_client.session, "request", fail_request)

        with pytest.raises(AnyRunAPIError, match="timeout"):
            mock_anyrun_client.get_task_report("550e8400-e29b-41d4-a716-446655440000")

    @responses.activate
    def test_malformed_json_response_raises_value_error(self, mock_anyrun_client):
        responses.add(
            responses.GET,
            "https://api.any.run/v1/report/550e8400-e29b-41d4-a716-446655440000/summary/json",
            body="not-json",
            status=200,
        )

        with pytest.raises(ValueError):
            mock_anyrun_client.get_task_report("550e8400-e29b-41d4-a716-446655440000")


class TestAnyRunClientPostMethods:
    @responses.activate
    def test_submit_url_posts_expected_payload(self, mock_anyrun_client):
        responses.add(
            responses.POST,
            "https://api.any.run/v1/analysis",
            json={"data": {"taskid": "11111111-2222-3333-4444-555555555555"}},
            status=200,
        )

        result = mock_anyrun_client.submit_url("https://example.test/payload")

        assert result["data"]["taskid"] == "11111111-2222-3333-4444-555555555555"
        assert responses.calls[0].request.body
        assert b"https://example.test/payload" in responses.calls[0].request.body

    def test_submit_file_nonexistent_path_raises_file_not_found(self, mock_anyrun_client):
        with pytest.raises(FileNotFoundError):
            mock_anyrun_client.submit_file("missing-file.bin")

    @responses.activate
    def test_submit_file_success(self, mock_anyrun_client, tmp_path: Path):
        sample = tmp_path / "sample.bin"
        sample.write_bytes(b"sample")
        responses.add(
            responses.POST,
            "https://api.any.run/v1/analysis",
            json={"data": {"taskid": "22222222-3333-4444-5555-666666666666"}},
            status=200,
        )

        result = mock_anyrun_client.submit_file(str(sample))

        assert result["data"]["taskid"] == "22222222-3333-4444-5555-666666666666"

    @responses.activate
    def test_submit_file_error_raises_api_error(self, mock_anyrun_client, tmp_path: Path):
        sample = tmp_path / "sample.bin"
        sample.write_bytes(b"sample")
        responses.add(
            responses.POST,
            "https://api.any.run/v1/analysis",
            body="bad request",
            status=400,
        )

        with pytest.raises(AnyRunAPIError, match="submit file 400"):
            mock_anyrun_client.submit_file(str(sample))

    def test_wait_for_task_returns_completed_report(self, mock_anyrun_client, monkeypatch, emotet_report):
        calls = {"count": 0}

        def fake_get_task_report(task_uuid):
            calls["count"] += 1
            return emotet_report

        monkeypatch.setattr(mock_anyrun_client, "get_task_report", fake_get_task_report)

        assert (
            mock_anyrun_client.wait_for_task("550e8400-e29b-41d4-a716-446655440000", poll_interval=1, max_wait=1)
            is emotet_report
        )
        assert calls["count"] == 1

    def test_invalid_task_uuid_is_rejected_before_request(self, mock_anyrun_client):
        with pytest.raises(ValueError, match="UUID"):
            mock_anyrun_client.get_task_report("not-a-uuid")

    def test_invalid_url_is_rejected_before_submit(self, mock_anyrun_client):
        with pytest.raises(ValueError, match="URL"):
            mock_anyrun_client.submit_url("ftp://example.test/payload")

    def test_invalid_history_pagination_is_rejected(self, mock_anyrun_client):
        with pytest.raises(ValueError, match="limit"):
            mock_anyrun_client.get_history(limit=0)

    def test_wait_for_task_times_out(self, mock_anyrun_client, monkeypatch):
        monkeypatch.setattr(
            mock_anyrun_client,
            "get_task_report",
            lambda task_uuid: {"data": {"analysis": {"status": "running"}}},
        )
        monkeypatch.setattr("anyrun_client.time.sleep", lambda seconds: None)

        with pytest.raises(TimeoutError):
            mock_anyrun_client.wait_for_task("550e8400-e29b-41d4-a716-446655440000", poll_interval=1, max_wait=1)
