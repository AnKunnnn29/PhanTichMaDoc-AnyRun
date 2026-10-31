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
    ".elf",
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


def validate_report(report, iocs) -> None:
    """Reject broken report structure instead of treating it as a clean sample."""
    import json

    if not isinstance(report, dict) or not isinstance(report.get("data"), dict):
        raise ValidationError("Báo cáo phải có object data/content của Any.Run")
    data = report["data"]
    if not isinstance(data.get("content"), dict) or not isinstance(data.get("analysis", {}), dict):
        raise ValidationError("data.content và data.analysis phải là object")
    content = data["content"]
    for key in ("network", "scores", "mainObject"):
        if key in content and not isinstance(content[key], dict):
            raise ValidationError(f"content.{key} phải là object")
    for key in ("processes", "dropped", "registry", "synchronization", "mitre"):
        _validate_rows(content.get(key, []), key)
    for key in ("connections", "httpRequests", "dnsRequests"):
        _validate_rows(content.get("network", {}).get(key, []), key)
    tags = data.get("analysis", {}).get("tags", [])
    if not isinstance(tags, list) or not all(isinstance(x, str) for x in tags):
        raise ValidationError("analysis.tags phải là danh sách chuỗi")
    if not isinstance(iocs, (list, dict)):
        raise ValidationError("IOC phải là object hoặc danh sách")
    _validate_rows(iocs if isinstance(iocs, list) else iocs.get("data", iocs.get("iocs", [])), "ioc")
    # Nested optional mappings are strict when present; missing values remain unknown.
    for owner, key in [(content.get("mainObject", {}), "hashes"), (content.get("scores", {}), "verdict"),
                       (content.get("scores", {}), "specs"), (data.get("analysis", {}), "options")]:
        if key in owner and not isinstance(owner[key], dict):
            raise ValidationError(f"{key} phải là object")
    verdict = content.get("scores", {}).get("verdict", {})
    options = data.get("analysis", {}).get("options", {})
    if "os" in options and not isinstance(options["os"], dict):
        raise ValidationError("analysis.options.os phải là object")
    for collection in ("processes", "dropped"):
        for row in content.get(collection, []):
            for key in ("hashes", "scores"):
                if key in row and not isinstance(row[key], dict):
                    raise ValidationError(f"{collection}.{key} phải là object")
            if "verdict" in row.get("scores", {}) and not isinstance(row["scores"]["verdict"], dict):
                raise ValidationError("process.scores.verdict phải là object")
    # Strings consumed by parsers/renderers must not be arbitrary JSON objects.
    text_fields = {"filename", "name", "key", "cmd", "type", "value", "uuid", "threat", "knownThreat",
                   "id", "tactic", "md5", "sha1", "sha256", "ip", "domain", "url", "version", "operation"}
    def check_scalars(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key in text_fields and not isinstance(value, str):
                    # mainObject.type is text; only data known to this schema is traversed.
                    raise ValidationError(f"{key} phải là chuỗi")
                check_scalars(value)
        elif isinstance(node, list):
            for value in node:
                check_scalars(value)
    check_scalars(data)
    check_scalars(iocs)
    if "threatLevel" in verdict and (type(verdict["threatLevel"]) is not int or not 0 <= verdict["threatLevel"] <= 4):
        raise ValidationError("threatLevel phải là số nguyên 0–4")
    try:
        size = len(json.dumps([report, iocs], ensure_ascii=False, allow_nan=False).encode("utf-8"))
    except (ValueError, TypeError, RecursionError) as exc:
        raise ValidationError("Báo cáo không phải JSON hữu hạn hợp lệ") from exc
    if size > MAX_REPORT_UPLOAD_BYTES:
        raise ValidationError("Tổng dữ liệu báo cáo vượt quá 10 MB")


def _validate_rows(rows, name):
    if not isinstance(rows, list) or len(rows) > 20000 or not all(isinstance(x, dict) for x in rows):
        raise ValidationError(f"{name} phải là danh sách object, tối đa 20000 mục")
