"""Local, transactional analysis snapshots and append-only analyst decisions.

Reviewer names are self-declared in this single-user prototype, not authenticated identities.
"""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from contextlib import contextmanager


@contextmanager
def _connect():
    from runtime_storage import reports_dir, cloud_mode
    path = reports_dir() / 'cases.sqlite3' if cloud_mode() else Path(os.getenv("IR_CASE_DB", str(reports_dir() / "cases.sqlite3")))
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=20)
    try:
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("CREATE TABLE IF NOT EXISTS cases (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, payload TEXT NOT NULL)")
        db.execute("CREATE INDEX IF NOT EXISTS cases_fingerprint ON cases(fingerprint)")
        db.execute("CREATE TABLE IF NOT EXISTS decisions (seq INTEGER PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id), "
                   "action_id TEXT NOT NULL, decision TEXT NOT NULL, reviewer TEXT NOT NULL, reason TEXT NOT NULL, "
                   "created_at TEXT NOT NULL, UNIQUE(case_id, action_id, seq))")
        with db:
            yield db
    finally:
        db.close()


def save_case(payload: dict) -> None:
    case_id = payload["case_id"]
    with _connect() as db:
        db.execute("INSERT OR IGNORE INTO cases(id,fingerprint,payload) VALUES (?,?,?)", (case_id, payload["analysis_fingerprint"], json.dumps(payload, ensure_ascii=False)))


def find_case(fingerprint: str) -> dict | None:
    with _connect() as db:
        row = db.execute("SELECT id FROM cases WHERE fingerprint=? ORDER BY rowid DESC LIMIT 1", (fingerprint,)).fetchone()
    return load_case(row[0]) if row else None


def load_case(case_id: str) -> dict | None:
    with _connect() as db:
        row = db.execute("SELECT payload FROM cases WHERE id=?", (case_id,)).fetchone()
        if not row:
            return None
        payload = json.loads(row[0])
        decisions = db.execute("SELECT seq,action_id,decision,reviewer,reason,created_at FROM decisions WHERE case_id=? ORDER BY seq", (case_id,)).fetchall()
    events = [dict(zip(("revision", "action_id", "decision", "reviewer", "reason", "created_at"), row)) for row in decisions]
    payload["review_history"] = events
    payload["review_revision"] = events[-1]["revision"] if events else 0
    by_id = {a["id"]: a for a in payload["playbook"]["actions"]}
    for event in events:
        action = by_id[event["action_id"]]
        action.update(status=event["decision"], review=event)
    return payload


def review_action(case_id: str, action_id: str, decision: str, reviewer: str, reason: str, expected_revision: int) -> dict:
    if decision not in {"approved", "rejected", "changes_requested"}:
        raise ValueError("Quyết định phải là approved, rejected hoặc changes_requested")
    if not isinstance(reviewer, str) or not reviewer.strip() or len(reviewer) > 120:
        raise ValueError("Cần tên người xem xét, tối đa 120 ký tự")
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 2000:
        raise ValueError("Cần lý do xem xét, tối đa 2000 ký tự")
    with _connect() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT payload FROM cases WHERE id=?", (case_id,)).fetchone()
        if not row:
            raise KeyError("Không tìm thấy phân tích")
        payload = json.loads(row[0])
        action = next((a for a in payload["playbook"]["actions"] if a["id"] == action_id), None)
        if not action:
            raise KeyError("Không tìm thấy khuyến nghị")
        current = db.execute("SELECT COALESCE(MAX(seq),0) FROM decisions WHERE case_id=?", (case_id,)).fetchone()[0]
        if type(expected_revision) is not int or current != expected_revision:
            raise RuntimeError("Kết quả đã được cập nhật; tải lại trước khi xem xét")
        if decision == "approved" and (not action.get("evidence_ids") or action.get("blocked")):
            raise ValueError("Khuyến nghị thiếu bằng chứng hoặc bị chặn; cần bổ sung dữ liệu")
        db.execute("INSERT INTO decisions(case_id,action_id,decision,reviewer,reason,created_at) VALUES (?,?,?,?,?,?)",
                   (case_id, action_id, decision, reviewer.strip(), reason.strip(), datetime.now(timezone.utc).isoformat()))
    return load_case(case_id)
