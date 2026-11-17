from __future__ import annotations

import copy
import io
import json
from pathlib import Path

import pytest

from ir_workspace.storage.case_store import load_case
from ir_workspace.analysis.evidence import validate_bundle

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
    # The browser copy omits the raw report; integrity is checked on the full server snapshot.
    assert all(src["content_omitted"] and "content" not in src for src in data["evidence_bundle"]["sources"])
    from ir_workspace.storage.case_store import load_case
    validate_bundle(load_case(data["case_id"])["evidence_bundle"])
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


def test_restored_slim_copy_does_not_replace_full_history_payload(flask_test_client):
    import ir_workspace.storage.history_store as history_store
    data = flask_test_client.get("/api/demo/wannacry").get_json()["data"]
    assert flask_test_client.post("/api/history/local/save", json={"data": data, "source": "browser:restore"}).get_json()["ok"]
    stored = next(i["payload"] for i in history_store.load_history() if i["payload"].get("case_id") == data["case_id"])
    assert all("content" in src for src in stored["evidence_bundle"]["sources"])
    reopened = flask_test_client.get("/api/cases/" + data["case_id"]).get_json()["data"]
    assert all("content" not in src for src in reopened["evidence_bundle"]["sources"])


def test_ghidra_listing_is_stored_with_the_case_and_reaches_every_export(flask_test_client, emotet_report, monkeypatch):
    import app as app_module
    from ir_workspace.analysis.code_evidence import build_code_evidence

    data = upload(flask_test_client, emotet_report)
    summary = _summary(comment="<b>x</b>")
    monkeypatch.setattr(app_module, "analyze_sample_with_ghidra", lambda path, timeout=180: {
        "triage": {"filename": "s.exe", "sha256": "c" * 64, "md5": "", "size": 4},
        "ghidra": {"status": "ok", "summary": summary}, "code_evidence": build_code_evidence(summary)})

    def analyze(case_id):
        return flask_test_client.post("/api/ghidra/analyze", content_type="multipart/form-data", data={
            "sample_file": (io.BytesIO(b"MZ.."), "s.exe"), "case_id": case_id})

    assert analyze("case-missing").status_code == 400
    attached = analyze(data["case_id"]).get_json()["data"]["static_analysis"]
    assert attached["hash_match"] is False and attached["tool"] == "Ghidra 12.1.2"
    assert load_case(data["case_id"])["static_analysis"]["sha256"] == "c" * 64
    assert upload(flask_test_client, emotet_report, force=False)["static_analysis"]["sha256"] == "c" * 64
    for fmt in ("markdown", "html", "pdf"):
        export = flask_test_client.post("/api/export", json={"format": fmt, "data": {"case_id": data["case_id"]}})
        raw = Path(export.get_json()["path"]).read_bytes()
        if fmt == "pdf":
            assert raw.startswith(b"%PDF")
            continue
        text = raw.decode("utf-8")
        # A code fence shows markup literally; HTML has to escape it.
        marker = ">> 0040102b  ff 15 00 a0 40 00"
        assert (marker if fmt == "markdown" else marker.replace(">", "&gt;")) in text
        assert fmt == "markdown" or "<b>x</b>" not in text


def _summary(comment="ADVAPI32.DLL::RegSetValueExA"):
    instruction = {"address": "0040102b", "bytes": "ff 15 00 a0 40 00",
                   "text": "CALL dword ptr [0x0040a000]", "comment": comment, "is_call": True}
    site = {"api": "RegSetValueExA", "base_api": "RegSetValue", "library": "ADVAPI32.DLL",
            "function": "FUN_00401000", "address": "0040102b", "instructions": [instruction]}
    return {"ghidra_version": "12.1.2", "call_counts": {"RegSetValueExA": 1}, "call_sites": [site]}


def test_ghidra_vm_result_is_imported_without_a_sample_on_the_host(flask_test_client, emotet_report):
    data = upload(flask_test_client, emotet_report)
    sha = data["file"]["sha256"]
    result = {"triage": {"filename": "sample.exe", "sha256": sha, "md5": "d" * 32, "size": 2048},
              "ghidra": {"status": "ok", "summary": _summary()}}

    def send(payload, case_id):
        return flask_test_client.post(
            "/api/ghidra/import", content_type="multipart/form-data",
            data={"result_file": (io.BytesIO(json.dumps(payload).encode()), "result.json"), "case_id": case_id})

    assert send(result, "case-missing").status_code == 400
    imported = send(result, data["case_id"]).get_json()
    assert imported["ok"] is True
    rec = imported["data"]["static_analysis"]
    assert rec["hash_match"] is True and rec["analysis_origin"] == "vm_headless"
    assert load_case(data["case_id"])["static_analysis"]["sha256"] == sha.lower()

    text = flask_test_client.post("/api/export", json={"format": "markdown", "data": {"case_id": data["case_id"]}})
    exported = Path(text.get_json()["path"]).read_text(encoding="utf-8")
    assert ">> 0040102b  ff 15 00 a0 40 00" in exported
    # A sample whose hash is not in the case still imports, but is flagged.
    result["triage"]["sha256"] = "e" * 64
    assert send(result, data["case_id"]).get_json()["data"]["static_analysis"]["hash_match"] is False
