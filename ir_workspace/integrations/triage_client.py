"""Read-only client for the public Triage API (https://tria.ge/docs/cloud-api/).

Only a sample hash or sample id is ever sent. Needs TRIAGE_API_KEY: the API answers
401 without one, including for public samples.
"""
from __future__ import annotations

import os
import re

import requests

from ir_workspace.integrations.triage_report import SAMPLE_ID_RE, _dict, _rows, _strings, triage_to_report

API = "https://tria.ge/api/v0"
MAX_RESPONSE_BYTES = 12 * 1024 * 1024
MAX_DYNAMIC_REPORTS = 2
TASK_RE = re.compile(r"behavioral\d{1,2}")


class TriageError(Exception):
    def __init__(self, message: str, status: int = 502, code: str = "triage_unavailable"):
        super().__init__(message)
        self.status, self.code = status, code


def configured() -> bool:
    return bool(os.getenv("TRIAGE_API_KEY", "").strip())


def _get(path: str, params: dict | None = None):
    key = os.getenv("TRIAGE_API_KEY", "").strip()
    if not key:
        raise TriageError("Chưa cấu hình TRIAGE_API_KEY trong .env", 400, "triage_not_configured")
    try:
        response = requests.get(API + path, params=params, headers={"Authorization": "Bearer " + key}, timeout=(5, 25))
    except requests.RequestException as exc:
        raise TriageError("Không kết nối được Triage") from exc
    if response.status_code in (401, 403):
        raise TriageError("Triage từ chối API key", 400, "triage_auth_error")
    if response.status_code == 404:
        raise TriageError("Triage không có dữ liệu này", 404, "triage_not_found")
    if response.status_code == 429:
        raise TriageError("Triage đang giới hạn số yêu cầu; thử lại sau", 429, "triage_rate_limited")
    if response.status_code != 200 or len(response.content) > MAX_RESPONSE_BYTES:
        raise TriageError("Triage trả về phản hồi không dùng được")
    try:
        return response.json()
    except ValueError as exc:
        raise TriageError("Triage trả về dữ liệu không phải JSON") from exc


def find_sample(sha256: str) -> str:
    """The most recently completed public analysis of this file."""
    sha256 = str(sha256).lower().strip()
    if not re.fullmatch(r"[0-9a-f]{64}", sha256):
        raise TriageError("Cần SHA256 hợp lệ để tìm trên Triage", 400, "invalid_hash")
    found = [row for row in _rows(_dict(_get("/search", {"query": "sha256:" + sha256, "limit": 20})).get("data"))
             if row.get("status") == "reported" and SAMPLE_ID_RE.fullmatch(str(row.get("id", "")))]
    if not found:
        raise TriageError("Triage chưa có báo cáo hoàn tất cho mẫu này", 404, "triage_not_found")
    return max(found, key=lambda row: str(row.get("completed", "")))["id"]


def behavioral_tasks(overview: dict) -> list[str]:
    names = [str(task.get("name", "")) for task in _rows(overview.get("tasks"))
             if task.get("kind", "behavioral") == "behavioral" and task.get("status", "reported") == "reported"]
    names += [name for target in _rows(overview.get("targets")) for name in _strings(target.get("tasks"))]
    short = [match.group() for match in map(TASK_RE.search, names) if match]
    return list(dict.fromkeys(short))[:MAX_DYNAMIC_REPORTS]


def fetch_report(sample_id: str) -> dict:
    """Overview plus the behavioural task reports, converted for the analysis pipeline."""
    if not SAMPLE_ID_RE.fullmatch(str(sample_id)):
        raise TriageError("Mã mẫu Triage không hợp lệ", 400, "invalid_sample_id")
    overview = _get(f"/samples/{sample_id}/overview.json")
    dynamics = []
    for task in behavioral_tasks(_dict(overview)):
        try:
            dynamics.append(_get(f"/samples/{sample_id}/{task}/report_triage.json"))
        except TriageError as exc:
            if exc.code != "triage_not_found":  # a task without a finished report is skipped, not fatal
                raise
    return triage_to_report(overview, dynamics)
