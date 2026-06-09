import pytest
import requests

from anyrun_public_report import (
    AnyRunPublicReportError,
    _download_public_vue_data,
    _extract_public_url,
    load_public_report,
)


TASK_UUID = "32c69330-3a1b-4891-99df-9bcb2f96f81e"
PUBLIC_URL = (
    "https://any.run/report/"
    "86f393d07fa3fe2d6027a59bbcea97747908f5aed1fa9fcfc6511b779c8dae3b/"
    f"{TASK_UUID}"
)


def test_extract_public_url_keeps_full_report_reference():
    assert _extract_public_url(PUBLIC_URL) == PUBLIC_URL


def test_uuid_only_error_explains_stale_frontend(tmp_path):
    with pytest.raises(AnyRunPublicReportError, match="Backend chỉ nhận được Task UUID"):
        load_public_report(TASK_UUID, source_ref=TASK_UUID, reports_dir=tmp_path)


def test_download_public_report_wraps_network_error(monkeypatch):
    def fail_request(*_args, **_kwargs):
        raise requests.ConnectionError("blocked")

    monkeypatch.setattr(requests, "get", fail_request)

    with pytest.raises(AnyRunPublicReportError, match="proxy hoặc firewall"):
        _download_public_vue_data(PUBLIC_URL)
