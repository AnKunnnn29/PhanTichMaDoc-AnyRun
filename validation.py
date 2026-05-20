"""
validation.py
~~~~~~~~~~~~~
Input validation helpers for API, CLI, and upload flows.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse


class ValidationError(ValueError):
    """Raised when user-provided input fails validation."""


UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-" r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

REPORT_EXTENSIONS = {".json", ".md", ".txt"}
SANDBOX_SAMPLE_EXTENSIONS = {
    ".7z",
    ".bin",
    ".dll",
    ".doc",
    ".docm",
    ".docx",
    ".exe",
    ".iso",
    ".js",
    ".msi",
    ".pdf",
    ".ps1",
    ".rar",
    ".rtf",
    ".scr",
    ".vbs",
    ".xls",
    ".xlsm",
    ".xlsx",
    ".zip",
}

MAX_REPORT_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_SANDBOX_UPLOAD_BYTES = 64 * 1024 * 1024


def validate_required_text(value: object, field_name: str, max_length: int = 4096) -> str:
    if value is None:
        raise ValidationError(f"Thiếu {field_name}")
    text = str(value).strip()
    if not text:
        raise ValidationError(f"Thiếu {field_name}")
    if len(text) > max_length:
        raise ValidationError(f"{field_name} vượt quá {max_length} ký tự")
    return text


def validate_api_key(value: object) -> str:
    key = validate_required_text(value, "API key", max_length=512)
    if key == "your_api_key_here":
        raise ValidationError("API key không hợp lệ")
    return key


def validate_task_uuid(value: object) -> str:
    task_uuid = validate_required_text(value, "Task UUID", max_length=64)
    if not UUID_RE.match(task_uuid):
        raise ValidationError("Task UUID không đúng định dạng UUID")
    return task_uuid


def validate_url(value: object) -> str:
    url = validate_required_text(value, "url", max_length=2048)
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValidationError("URL phải bắt đầu bằng http:// hoặc https://")
    return url


def validate_uploaded_filename(
    filename: str | None,
    allowed_extensions: set[str],
    field_name: str = "file",
) -> str:
    clean_name = Path(filename or "").name
    if not clean_name:
        raise ValidationError(f"Thiếu tên {field_name}")
    suffix = Path(clean_name).suffix.lower()
    if suffix not in allowed_extensions:
        allowed = ", ".join(sorted(allowed_extensions))
        raise ValidationError(f"Định dạng {field_name} không được hỗ trợ. Chỉ chấp nhận: {allowed}")
    return clean_name


def validate_upload_size(size: int, max_bytes: int, field_name: str = "file") -> None:
    if size <= 0:
        raise ValidationError(f"{field_name} đang rỗng")
    if size > max_bytes:
        max_mb = max_bytes / (1024 * 1024)
        raise ValidationError(f"{field_name} vượt quá giới hạn {max_mb:.0f} MB")
