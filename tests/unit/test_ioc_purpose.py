from __future__ import annotations

import copy

import pytest

from ir_workspace.ai.analysis_agent import NETWORK_PURPOSE, UNKNOWN_PURPOSE, _baseline, investigate, validate_findings
from ir_workspace.analysis.analysis_pipeline import research_markdown, run_pipeline
from ir_workspace.analysis.evidence import collect_evidence
from ir_workspace.reporting.reporter import _report_payload

pytestmark = pytest.mark.unit


def test_every_rule_based_finding_states_a_purpose(emotet_report, emotet_ioc):
    bundle = collect_evidence(emotet_report, emotet_ioc)
    rows = {item["type"]: _baseline(item) for item in bundle["observables"]}

    assert all(row["purpose"].strip() for row in rows.values())
    # A hash identifies the file; it is not something the sample uses.
    assert "nhận diện" in rows["sha256"]["purpose"]
    assert rows["ip"]["purpose"] == UNKNOWN_PURPOSE


def test_network_purpose_follows_the_destination_profile(emotet_report):
    item = next(o for o in collect_evidence(emotet_report, {})["observables"] if o["type"] == "ip")
    profile = {"role": "config_c2", "severity": "critical", "summary": "s", "impact": "i", "verify": "v"}

    assert _baseline(item, profile)["purpose"] == NETWORK_PURPOSE["config_c2"]
    assert "chưa có bằng chứng" in _baseline(item, {**profile, "role": "benign_infrastructure"})["purpose"]
    assert _baseline(item, {**profile, "role": "unverified_destination"})["purpose"] == UNKNOWN_PURPOSE


def test_model_purpose_is_kept_and_a_missing_one_falls_back_to_the_rule(monkeypatch, emotet_report):
    monkeypatch.setenv("AGENT_PROVIDER", "ollama")
    bundle = collect_evidence(emotet_report, {})
    bundle["observables"] = bundle["observables"][:2]
    rows = [_baseline(x) for x in bundle["observables"]]
    expected = rows[1]["purpose"]
    rows[0]["purpose"] = "Tải payload giai đoạn hai."
    del rows[1]["purpose"]
    responses = iter([{"tool": "get_evidence", "evidence_ids": [e for r in rows for e in r["evidence_ids"]]},
                      {"tool": "submit_findings", "findings": rows}])
    monkeypatch.setattr("ir_workspace.ai.analysis_agent._call_model", lambda *_: next(responses))

    findings = investigate(bundle)["findings"]

    assert findings[0]["purpose"] == "Tải payload giai đoạn hai." and findings[1]["purpose"] == expected


def test_unusable_purpose_is_rejected_and_stored_results_without_one_stay_valid(emotet_report):
    bundle = collect_evidence(emotet_report, {})
    bundle["observables"] = bundle["observables"][:1]
    row = _baseline(bundle["observables"][0])
    ids = {row["ioc_id"]}
    legacy = copy.deepcopy(row)
    del legacy["purpose"]

    validate_findings([legacy], bundle, ids)
    with pytest.raises(ValueError, match="purpose"):
        validate_findings([{**row, "purpose": ["a list"]}], bundle, ids)


def test_purpose_reaches_the_markdown_export(emotet_report, emotet_ioc):
    payload = _report_payload(*run_pipeline(emotet_report, emotet_ioc, source="test"))
    markdown = research_markdown(payload)

    assert "| IOC ID | Vai trò dự kiến | Mục đích |" in markdown
    assert all(f["purpose"] for f in payload["agent_analysis"]["findings"])


def test_single_shot_ioc_reads_preloaded_evidence_once(monkeypatch, emotet_report):
    import json
    bundle = collect_evidence(emotet_report, {})
    bundle['observables'] = bundle['observables'][:2]
    monkeypatch.setenv('AGENT_PROVIDER', 'ollama')
    monkeypatch.setenv('AGENT_STRATEGY', 'single_shot')
    calls = []
    def fake(messages, settings):
        calls.append(messages)
        context = json.loads(messages[1]['content'])
        refs = {e['id'] for e in context['evidence']}
        findings = [_baseline(o) for o in bundle['observables']]
        for row in findings:
            row['evidence_ids'] = [i for i in row['evidence_ids'] if i in refs]
        return {'tool': 'submit_findings', 'findings': findings}
    monkeypatch.setattr('ir_workspace.ai.analysis_agent._call_model', fake)
    result = investigate(bundle)
    assert len(calls) == 1 and result['mode'] == 'llm'
