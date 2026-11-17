from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from ir_workspace.storage.case_store import load_case

pytestmark = pytest.mark.integration
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _upload(client, document, name="report.json"):
    response = client.post("/api/analyze/json", content_type="multipart/form-data",
                           data={"report_file": (io.BytesIO(json.dumps(document).encode()), name)})
    assert response.status_code == 200, response.get_json()
    return response.get_json()["data"]


def _triage(sha256=None):
    overview = json.loads((FIXTURES / "triage_overview.json").read_text(encoding="utf-8"))
    dynamic = json.loads((FIXTURES / "triage_dynamic.json").read_text(encoding="utf-8"))
    if sha256:
        overview["sample"]["sha256"] = sha256
    return overview, dynamic


def _file(document, name):
    return io.BytesIO(json.dumps(document).encode()), name


def test_triage_overview_uploaded_as_a_report_runs_the_pipeline(flask_test_client):
    data = _upload(flask_test_client, _triage()[0], "overview.json")

    assert data["file"]["sha256"] == "c34af1f1f238747d6839ce6857138e97d722443c4e2a794c072c236228ceaa07"
    assert data["threat"]["threat_name"].lower() == "wannacry"
    assert any(p["value"] == "185.173.38.57" for p in data["network_profiles"].values())


def test_uploaded_triage_report_is_compared_stored_and_exported(flask_test_client, emotet_report):
    case = _upload(flask_test_client, emotet_report)
    overview, dynamic = _triage(case["file"]["sha256"])
    url = f"/api/cases/{case['case_id']}/compare/triage"

    response = flask_test_client.post(url, content_type="multipart/form-data", data={
        "report_file": _file(overview, "overview.json"), "dynamic_file": _file(dynamic, "report_triage.json")})
    comparison = response.get_json()["data"]["sandbox_comparison"]

    assert response.status_code == 200
    assert comparison["labels"] == {"a": "Any.Run", "b": "Triage"} and comparison["relation"] == "same_file"
    assert comparison["sandbox_url"] == "https://tria.ge/260317-xlg6lafz9j"
    assert {d["id"] for d in comparison["dimensions"]} >= {"family", "attack_techniques", "impact_categories"}
    assert load_case(case["case_id"])["sandbox_comparison"]["cases"]["b"] == comparison["cases"]["b"]
    for fmt in ("markdown", "html"):
        export = flask_test_client.post("/api/export", json={"format": fmt, "data": {"case_id": case["case_id"]}})
        assert "Đối chiếu đa nguồn: Any.Run và Triage" in Path(export.get_json()["path"]).read_text(encoding="utf-8")


def test_comparison_refuses_another_sample_and_unknown_cases(flask_test_client, emotet_report):
    case = _upload(flask_test_client, emotet_report)
    send = lambda case_id: flask_test_client.post(  # noqa: E731
        f"/api/cases/{case_id}/compare/triage", content_type="multipart/form-data",
        data={"report_file": _file(_triage()[0], "overview.json")})

    assert send("case-missing").status_code == 404
    refused = send(case["case_id"])
    assert refused.status_code == 400 and "không cùng một mẫu" in refused.get_json()["error"]
    assert "sandbox_comparison" not in load_case(case["case_id"])


def test_comparison_fetches_from_triage_by_the_case_hash(flask_test_client, emotet_report, monkeypatch):
    import app as app_module
    from ir_workspace.integrations.triage_report import triage_to_report

    case = _upload(flask_test_client, emotet_report)
    overview, dynamic = _triage(case["file"]["sha256"])
    asked = []
    monkeypatch.setattr(app_module, "find_triage_sample", lambda sha: asked.append(sha) or "260317-xlg6lafz9j")
    monkeypatch.setattr(app_module, "fetch_triage_report", lambda sample_id: triage_to_report(overview, [dynamic]))

    response = flask_test_client.post(f"/api/cases/{case['case_id']}/compare/triage")

    assert response.status_code == 200 and asked == [case["file"]["sha256"].lower()]


def test_comparison_without_a_key_says_how_to_configure_it(flask_test_client, emotet_report, monkeypatch):
    monkeypatch.delenv("TRIAGE_API_KEY", raising=False)
    case = _upload(flask_test_client, emotet_report)

    response = flask_test_client.post(f"/api/cases/{case['case_id']}/compare/triage")

    assert response.status_code == 400 and response.get_json()["code"] == "triage_not_configured"
