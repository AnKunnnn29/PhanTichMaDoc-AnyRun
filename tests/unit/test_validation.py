from __future__ import annotations

import pytest

from validation import (
    REPORT_EXTENSIONS,
    ValidationError,
    validate_api_key,
    validate_task_uuid,
    validate_upload_size,
    validate_uploaded_filename,
    validate_url,
)

pytestmark = pytest.mark.unit


def test_validate_api_key_rejects_placeholder():
    with pytest.raises(ValidationError):
        validate_api_key("your_api_key_here")


def test_validate_task_uuid_accepts_uuid_and_rejects_free_text():
    assert validate_task_uuid("550e8400-e29b-41d4-a716-446655440000")
    with pytest.raises(ValidationError, match="UUID"):
        validate_task_uuid("task-uuid")


@pytest.mark.parametrize("url", ["https://example.test/a", "http://example.test"])
def test_validate_url_accepts_http_and_https(url):
    assert validate_url(url) == url


@pytest.mark.parametrize("url", ["ftp://example.test/a", "example.test/a", ""])
def test_validate_url_rejects_unsafe_or_invalid_schemes(url):
    with pytest.raises(ValidationError):
        validate_url(url)


def test_validate_uploaded_filename_strips_paths_and_checks_extension():
    assert validate_uploaded_filename("../report.json", REPORT_EXTENSIONS) == "report.json"
    with pytest.raises(ValidationError):
        validate_uploaded_filename("report.exe", REPORT_EXTENSIONS)


def test_validate_upload_size_rejects_empty_and_oversized_content():
    with pytest.raises(ValidationError, match="rỗng"):
        validate_upload_size(0, 10)
    with pytest.raises(ValidationError, match="vượt quá"):
        validate_upload_size(11, 10)
