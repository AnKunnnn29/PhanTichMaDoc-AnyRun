from __future__ import annotations

import copy
import io
import json
from pathlib import Path

import pytest

from case_store import load_case
from evidence import validate_bundle

pytestmark = pytest.mark.integration


def upload(client, report, force=False):
    response = client.post("/api/analyze/json", data={
        "report_file": (io.BytesIO(json.dumps(report).encode()), "report.json"),
        "force_analyze": "true" if force else "false"}, content_type="multipart/form-data")
    assert response.status_code == 200, response.get_json()
    return response.get_json()["data"]


def test_cache_never_reuses_family_sample_or_changed_same_task(flask_test_client, emotet_report):
    a = upload(flask_test_client, emotet_report)
    b_report = copy.deepcopy(emotet_report)
    b_report["data"]["content"]["mainObject"]["hashes"]["sha256"] = "b" * 64
    b_report["data"]["analysis"]["uuid"] = "22222222-2222-2222-2222-222222222222"
    b = upload(flask_test_client, b_report)
    assert a["case_id"] != b["case_id"]
    assert b["task_uuid"] == b_report["data"]["analysis"]["uuid"]
    assert b["file"]["sha256"] == "b" * 64
    assert upload(flask_test_client, b_report)["case_id"] == b["case_id"]
    assert upload(flask_test_client, b_report, force=True)["case_id"] != b["case_id"]


def test_review_persists_rejects_stale_and_exports_server_snapshot(flask_test_client, emotet_report):
    data = upload(flask_test_client, emotet_report)
    action = next(a for a in data["playbook"]["actions"] if not a["blocked"])
    body = {"action_id": action["id"], "decision": "approved", "reviewer": "Analyst test",
            "reason": "Reviewed sample evidence; verify endpoint before action", "expected_revision": 0}
    path = f"/api/cases/{data['case_id']}/review"
    response = flask_test_client.post(path, json=body)
    assert response.status_code == 200
    stored = load_case(data["case_id"])
    assert stored["review_history"][0]["reviewer"] == "Analyst test"
    assert flask_test_client.post(path, json=body).status_code == 409
    fetched = flask_test_client.get(f"/api/cases/{data['case_id']}").get_json()["data"]
    assert fetched["review_revision"] > 0
    for fmt in ("json", "markdown"):
        exported = flask_test_client.post("/api/export", json={"format": fmt, "data": {"case_id": data["case_id"], "fake": True}})
        assert exported.status_code == 200
        text = Path(exported.get_json()["path"]).read_text(encoding="utf-8")
        assert "Analyst test" in text and "ev-" in text and "approved" in text
        assert '"fake"' not in text
        download = flask_test_client.get(exported.get_json()["download_url"])
        assert download.status_code == 200
        assert "attachment" in download.headers["Content-Disposition"]
        assert b"Analyst test" in download.data
    assert flask_test_client.get("/api/exports/cases.sqlite3").status_code == 404


@pytest.mark.parametrize("decision,reviewer,reason", [("execute", "A", "R"), ("approved", "", "R"), ("approved", "A", "")])
def test_review_requires_decision_reviewer_and_reason(flask_test_client, emotet_report, decision, reviewer, reason):
    data = upload(flask_test_client, emotet_report)
    r = flask_test_client.post(f"/api/cases/{data['case_id']}/review", json={"action_id": data["playbook"]["actions"][0]["id"],
        "decision": decision, "reviewer": reviewer, "reason": reason, "expected_revision": 0})
    assert r.status_code == 400


@pytest.mark.parametrize("malware", ["emotet", "wannacry", "redline"])
def test_three_demos_have_full_evidence_agent_and_review_metadata(flask_test_client, malware):
    data = flask_test_client.get(f"/api/demo/{malware}").get_json()["data"]
    validate_bundle(data["evidence_bundle"])
    assert data["agent_analysis"]["findings"]
    assert data["nist"]["revision"] == "SP 800-61 Rev.3"
    assert all(a["status"] == "pending" and a["id"] for a in data["playbook"]["actions"])
    assert all(m["evidence_ids"] for m in data["mitre_mappings"])


def test_empty_and_broken_json_rejected(flask_test_client):
    for raw in (b"{}", b"not-json", b"[]"):
        r = flask_test_client.post("/api/analyze/json", data={"report_file": (io.BytesIO(raw), "bad.json")})
        assert r.status_code == 400


def test_forwarded_header_does_not_bypass_rate_limit(flask_test_client):
    for n in range(35):
        response = flask_test_client.post("/api/analyze/json", data={}, headers={"X-Forwarded-For": f"spoof-{n}"})
    assert response.status_code == 429
