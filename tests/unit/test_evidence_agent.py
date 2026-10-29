from __future__ import annotations

import copy

import pytest

from analysis_agent import _baseline, investigate, validate_findings
from analysis_pipeline import analysis_key, build_behavior, run_pipeline
from analyzer import MalwareAnalyzer
from evidence import collect_evidence, normalize, validate_bundle
from markdown_importer import markdown_to_anyrun_report
from mitre_mapping import map_evidence

pytestmark = pytest.mark.unit


def test_every_observable_is_bound_to_verifiable_source(emotet_report, emotet_ioc):
    bundle = collect_evidence(emotet_report, emotet_ioc)
    validate_bundle(bundle)
    assert {o["type"] for o in bundle["observables"]} >= {"ip", "domain", "process", "registry", "file", "sha256"}
    bundle["evidence"][0]["value"] = "tampered"
    with pytest.raises(ValueError):
        validate_bundle(bundle)


def test_source_tampering_and_missing_binding_rejected(emotet_report):
    bundle = collect_evidence(emotet_report, {})
    bundle["sources"][0]["content"]["data"]["content"]["mainObject"]["filename"] = "changed"
    with pytest.raises(ValueError, match="hash"):
        validate_bundle(bundle)
    bundle = collect_evidence(emotet_report, {})
    bundle["observables"][0]["evidence_ids"] = ["ev-does-not-exist"]
    with pytest.raises(ValueError):
        validate_bundle(bundle)


@pytest.mark.parametrize("kind,value,valid,expected", [
    ("domain", "EXAMPLE.COM.", True, "example.com"), ("ip", "999.1.1.1", False, "999.1.1.1"),
    ("ip", "2001:db8::1", True, "2001:db8::1"), ("sha256", "A" * 64, True, "a" * 64),
    ("url", "HTTPS://EXAMPLE.COM/Path?Q=1", True, "https://example.com/Path?Q=1"),
    ("url", "javascript:alert(1)", False, "javascript:alert(1)"), ("file", "bad\npath", False, "bad\npath"),
    ("mitre", "T999", False, "T999"), ("domain", "bad..com", False, "bad..com"),
])
def test_normalization(kind, value, valid, expected):
    assert normalize(kind, value) == (expected, valid)


def test_normalized_values_merge_but_keep_original_sources(emotet_report):
    emotet_report["data"]["content"]["network"] = {"dnsRequests": [{"domain": "EXAMPLE.COM."}, {"domain": "example.com"}]}
    bundle = collect_evidence(emotet_report, {})
    row = next(x for x in bundle["observables"] if x["type"] == "domain")
    assert row["value"] == "example.com"
    assert len(row["evidence_ids"]) == 2


def test_raw_schema_is_not_a_clean_verdict():
    with pytest.raises(ValueError):
        MalwareAnalyzer().parse_report({}, {})
    result = MalwareAnalyzer().parse_report({"data": {"content": {}}}, {})
    assert result.threat_info.verdict == "Unknown"


@pytest.mark.parametrize("bad", [[], {"data": []}, {"data": {"content": []}},
    {"data": {"content": {"network": {"connections": ["not-object"]}}}},
    {"data": {"content": {"scores": {"verdict": {"threatLevel": "3"}}}}}])
def test_invalid_report_structure_rejected(bad):
    with pytest.raises(ValueError):
        MalwareAnalyzer().parse_report(bad, {})


def test_text_negations_and_documentation_do_not_invent_events():
    report = markdown_to_anyrun_report("Filename: benign.exe\nNo ransomware behavior. No PowerShell execution.\n"
        "Reference C:\\Windows\\System32\\cmd.exe https://learn.microsoft.com/\n")
    result, playbook = run_pipeline(report, {})
    assert result.threat_info.verdict == "Unknown"
    assert not result.threat_info.mitre_techniques
    assert not result.processes.processes and not result.processes.dropped_files
    assert not playbook.ioc_blocklist["domains"]
    assert not any(a.commands for a in playbook.actions)


def test_text_sections_keep_lines_and_distinct_content_ids():
    a = markdown_to_anyrun_report("Filename: a.exe\n## Network\nEXAMPLE.COM\n## Processes\ncmd.exe\n## MITRE\nT1059.003")
    b = markdown_to_anyrun_report("Filename: b.exe")
    assert a["data"]["analysis"]["uuid"] != b["data"]["analysis"]["uuid"]
    bundle = collect_evidence(a, {})
    validate_bundle(bundle)
    assert next(x for x in bundle["evidence"] if x["type"] == "domain")["source_lines"] == [3]
    assert a["data"]["content"]["processes"][0]["pid"] is None


def test_filename_cannot_change_verdict_or_family(emotet_report):
    content = emotet_report["data"]["content"]
    content["mainObject"]["filename"] = "wannacry-notes.txt"
    content["scores"] = {"verdict": {"threatLevel": 0, "threat": "No threats detected"}}
    emotet_report["data"]["analysis"]["tags"] = []
    result = MalwareAnalyzer().parse_report(emotet_report, {})
    assert result.threat_info.verdict == "No threats detected"
    assert result.threat_info.threat_name != "WannaCry"


def test_unknown_mitre_and_benign_registry_are_not_promoted(emotet_report):
    c = emotet_report["data"]["content"]
    c["mitre"] = [{"id": "T9999"}]
    c["processes"] = []
    c["registry"] = [{"key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "operation": "read"}]
    mappings, meta = map_evidence(collect_evidence(emotet_report, {}))
    assert meta["version"] == "19.2"
    assert mappings[0]["catalog_validation"] == "unknown_or_retired"
    assert not any(m["technique_id"] == "T1547.001" for m in mappings)


def test_behavior_uses_explicit_process_relations_only(emotet_report):
    c = emotet_report["data"]["content"]
    c["processes"] = [{"pid": 1, "name": "parent.exe"}, {"pid": 2, "ppid": 1, "name": "child.exe"}]
    c["network"] = {"connections": [{"ip": "192.0.2.1", "pid": 2, "timestamp": "2026-10-29T00:00:00Z"}]}
    chain = build_behavior(collect_evidence(emotet_report, {}))
    assert len(chain["relations"]) == 2
    assert any(e["timestamp"] for e in chain["events"])
    assert any(e["order_basis"] == "source_order_not_chronology" for e in chain["events"])


def test_rules_mode_is_labelled_and_does_not_call_network(monkeypatch, emotet_report):
    monkeypatch.setattr("analysis_agent._call_model", lambda *_: pytest.fail("Unexpected network"))
    agent = investigate(collect_evidence(emotet_report, {}))
    assert agent["mode"] == "rule_based"
    assert agent["validation"]["semantic_accuracy"] == "requires_analyst_review"


def test_llm_reads_evidence_and_returns_validated_findings(monkeypatch, emotet_report):
    monkeypatch.setenv("AGENT_PROVIDER", "ollama")
    bundle = collect_evidence(emotet_report, {})
    # Use a small batch to exercise real orchestration without model/network access.
    bundle["observables"] = bundle["observables"][:2]
    rows = [_baseline(x) for x in bundle["observables"]]
    responses = iter([{"tool": "get_evidence", "evidence_ids": [e for r in rows for e in r["evidence_ids"]]},
                      {"tool": "submit_findings", "findings": rows}])
    monkeypatch.setattr("analysis_agent._call_model", lambda *_: next(responses))
    result = investigate(bundle)
    assert result["mode"] == "llm"
    assert [x["tool"] for x in result["tool_trace"]] == ["interpret_observables", "get_evidence", "submit_findings"]


@pytest.mark.parametrize("answer", [{"tool": "execute_command"}, {"tool": "get_evidence", "evidence_ids": ["invented"]},
                                   {"tool": "submit_findings", "findings": []}])
def test_llm_invalid_tools_and_output_fall_back_explicitly(monkeypatch, emotet_report, answer):
    monkeypatch.setenv("AGENT_PROVIDER", "ollama")
    monkeypatch.setattr("analysis_agent._call_model", lambda *_: answer)
    result = investigate(collect_evidence(emotet_report, {}))
    assert result["mode"] == "fallback" and result["warnings"]
    assert all(x["origin"] == "rule_based" for x in result["findings"])


def test_agent_cannot_reference_other_ioc_evidence(emotet_report):
    bundle = collect_evidence(emotet_report, {})
    items = [x for x in bundle["observables"] if x["type"] != "mitre"]
    rows = [_baseline(x) for x in items]
    rows[0]["evidence_ids"] = rows[1]["evidence_ids"]
    with pytest.raises(ValueError):
        validate_findings(rows, bundle, {x["id"] for x in items})


def test_full_input_and_config_define_cache_key(monkeypatch, emotet_report):
    original = analysis_key(emotet_report, {})
    changed = copy.deepcopy(emotet_report)
    changed["data"]["analysis"]["duration"] += 1
    assert analysis_key(changed, {}) != original
    monkeypatch.setenv("AGENT_PROVIDER", "ollama")
    assert analysis_key(emotet_report, {}) != original


def test_agent_repairs_enum_arrays_within_step_budget(monkeypatch, emotet_report):
    monkeypatch.setenv("AGENT_PROVIDER", "deepseek")
    bundle = collect_evidence(emotet_report, {})
    bundle["observables"] = bundle["observables"][:1]
    row = _baseline(bundle["observables"][0])
    invalid = {**row, "role": [row["role"]]}
    replies = iter([{"tool": "get_evidence", "evidence_ids": row["evidence_ids"]},
                    {"tool": "submit_findings", "findings": [invalid]},
                    {"tool": "submit_findings", "findings": [row]}])
    monkeypatch.setattr("analysis_agent._call_model", lambda *_: next(replies))
    output = investigate(bundle)
    assert output["mode"] == "llm"
    assert any(e["status"] == "rejected" for e in output["tool_trace"])
