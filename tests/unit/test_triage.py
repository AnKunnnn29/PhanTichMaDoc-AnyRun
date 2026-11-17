import copy
import json
from pathlib import Path

import pytest

from ir_workspace.analysis.sandbox_compare import compare_payloads, comparison_lines, relation
from ir_workspace.integrations import triage_client
from ir_workspace.integrations.hash_lookup import vendor_verdicts
from ir_workspace.integrations.triage_report import TriageReportError, is_triage_report, triage_to_report

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
SHA = "c34af1f1f238747d6839ce6857138e97d722443c4e2a794c072c236228ceaa07"


@pytest.fixture
def overview():
    return json.loads((FIXTURES / "triage_overview.json").read_text(encoding="utf-8"))


@pytest.fixture
def dynamic():
    return json.loads((FIXTURES / "triage_dynamic.json").read_text(encoding="utf-8"))


def test_overview_is_recognised_and_anyrun_reports_are_not(overview):
    assert is_triage_report(overview)
    assert not is_triage_report({"data": {"content": {}}, "sample": {"sha256": SHA}})
    assert not is_triage_report({"sample": {}, "analysis": {}})
    with pytest.raises(TriageReportError):
        triage_to_report({"sample": {"id": "x"}})


def test_dynamic_report_supplies_processes_network_files_and_techniques(overview, dynamic):
    report = triage_to_report(overview, [dynamic])
    analysis, content = report["data"]["analysis"], report["data"]["content"]

    assert analysis["sandbox"] == {"name": "Triage", "sample_id": "260317-xlg6lafz9j", "score": 10,
                                   "url": "https://tria.ge/260317-xlg6lafz9j", "dynamic_reports": 1}
    assert content["mainObject"]["hashes"]["sha256"] == SHA
    assert content["scores"]["verdict"]["threatLevel"] == 2
    assert content["scores"]["specs"]["knownThreat"] == "wannacry"
    assert [(p["name"], p["pid"], p["ppid"]) for p in content["processes"]] == [
        ("Install.exe", 4120, 3300), ("attrib.exe", 4388, 4120), ("schtasks.exe", 4500, 4120)]
    assert content["processes"][1]["cmd"] == "attrib +h ."
    # The resolver flow is transport; the address a domain resolved to stays with that domain.
    assert [(c["ip"], c["port"], c["pid"]) for c in content["network"]["connections"]] == [("185.173.38.57", 80, 4120)]
    assert content["network"]["dnsRequests"][0]["ips"] == ["104.16.173.80"]
    assert content["network"]["httpRequests"][0]["userAgent"] == "Mozilla/5.0"
    # Memory dumps have no on-disk path and are not dropped files.
    assert [d["filename"] for d in content["dropped"]] == ["C:\\Windows\\rar.exe"]
    assert [m["id"] for m in content["mitre"]] == ["T1486", "T1053.005", "T1222"]
    assert "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94" in content["malwareConfig"][0]


def test_overview_alone_keeps_destinations_without_inventing_ports_or_processes(overview):
    content = triage_to_report(overview)["data"]["content"]

    assert content["processes"] == [] and content["dropped"] == []
    assert content["network"]["connections"] == [{"ip": "185.173.38.57", "port": None, "pid": None, "process": "",
                                                  "domain": "", "asn": "", "country": "", "reputation": ""}]
    assert content["network"]["httpRequests"][0]["url"] == "http://185.173.38.57/payload.bin"


def test_hostile_field_types_do_not_break_conversion(overview):
    overview.update(tasks=[{"name": 5, "tags": "x"}, "junk"], signatures={"a": 1}, extracted="no",
                    targets=[{"signatures": [{"name": ["x"], "ttp": "T1486"}], "iocs": {"ips": "1.2.3.4"}}])
    overview["sample"]["size"] = "big"

    content = triage_to_report(overview, ["junk", {"processes": {"x": 1}, "network": []}])["data"]["content"]

    assert content["mainObject"]["size"] == 0 and content["mitre"] == []


def _payload(source, main, family, impacts, techniques, dropped=(), profiles=()):
    evidence = [{"type": "sha256", "value": h, "source_path": "/data/content/dropped/0/hashes/sha256"} for h in dropped]
    return {"source": source, "case_id": "case-" + source, "file": {"sha256": main},
            "threat": {"threat_name": family}, "evidence_bundle": {"evidence": evidence},
            "impact_analysis": {"categories": [{"id": i, "title": i.title()} for i in impacts]},
            "mitre_mappings": [{"technique_id": t} for t in techniques],
            "network_profiles": {str(n): {"value": v, "role": r} for n, (v, r) in enumerate(profiles)}}


def test_comparison_reports_both_sides_and_each_side_alone():
    a = _payload("import", "a" * 64, "WannaCry", ["data_encryption", "persistence"], ["T1486", "T1059.001"],
                 dropped=[SHA], profiles=[("8.8.8.8", "benign_infrastructure"), ("1.1.1.1", "config_c2")])
    b = _payload("triage:260317-x", SHA, "wannacry", ["persistence"], ["T1486"],
                 profiles=[("1.1.1.1", "known_c2"), ("9.9.9.9", "payload_download")])

    result = compare_payloads(a, b)
    by_id = {d["id"]: d for d in result["dimensions"]}

    assert result["labels"] == {"a": "Any.Run", "b": "Triage"}
    assert result["relation"] == "sample_in_other_run"
    assert by_id["family"]["both"] == ["wannacry"] and by_id["family"]["jaccard"] == 1.0
    assert by_id["attack_techniques"]["only_a"] == ["T1059.001"] and by_id["attack_techniques"]["jaccard"] == 0.5
    assert by_id["impact_categories"]["only_a"] == ["Data_Encryption"]
    # Benign infrastructure is not a finding to agree or disagree on.
    assert by_id["suspicious_destinations"]["both"] == ["1.1.1.1"]
    assert by_id["suspicious_destinations"]["only_b"] == ["9.9.9.9"]
    assert by_id["c2"]["jaccard"] == 1.0
    assert "Jaccard 0.5" in "\n".join(comparison_lines({"sandbox_comparison": result}))


def test_no_observation_on_either_side_is_not_scored_as_agreement():
    a = _payload("import", SHA, "", [], [])
    result = compare_payloads(a, copy.deepcopy(a) | {"source": "triage:1"})

    assert result["relation"] == "same_file"
    assert all(d["jaccard"] is None for d in result["dimensions"]) and result["mean_jaccard"] is None


def test_unrelated_samples_are_refused():
    a, b = _payload("import", "a" * 64, "x", [], []), _payload("triage:1", "b" * 64, "x", [], [])

    assert relation(a, b) == ""
    with pytest.raises(ValueError):
        compare_payloads(a, b)
    assert comparison_lines({}) == []


class _Response:
    def __init__(self, status, body):
        self.status_code, self._body, self.content = status, body, b"{}"

    def json(self):
        return self._body


def test_client_searches_by_hash_and_reads_behavioural_reports(monkeypatch, overview, dynamic):
    calls = []
    answers = {"/search": {"data": [{"id": "250101-aaaaaaaaaa", "status": "reported", "completed": "2025-01-01T00:00:00Z"},
                                    {"id": "260317-xlg6lafz9j", "status": "reported", "completed": "2026-03-17T00:00:00Z"},
                                    {"id": "260401-bbbbbbbbbb", "status": "running"}]},
               "/samples/260317-xlg6lafz9j/overview.json": overview,
               "/samples/260317-xlg6lafz9j/behavioral1/report_triage.json": dynamic}

    def fake_get(url, params=None, headers=None, timeout=None):
        calls.append((url.removeprefix(triage_client.API), params, headers))
        return _Response(200, answers[url.removeprefix(triage_client.API)])

    monkeypatch.setenv("TRIAGE_API_KEY", "test-key")
    monkeypatch.setattr(triage_client.requests, "get", fake_get)

    sample_id = triage_client.find_sample(SHA.upper())
    report = triage_client.fetch_report(sample_id)

    assert sample_id == "260317-xlg6lafz9j"
    assert calls[0] == ("/search", {"query": "sha256:" + SHA, "limit": 20}, {"Authorization": "Bearer test-key"})
    assert [c[0] for c in calls[1:]] == ["/samples/260317-xlg6lafz9j/overview.json",
                                         "/samples/260317-xlg6lafz9j/behavioral1/report_triage.json"]
    assert len(report["data"]["content"]["processes"]) == 3


@pytest.mark.parametrize("status,code", [(401, "triage_auth_error"), (404, "triage_not_found"),
                                         (429, "triage_rate_limited"), (500, "triage_unavailable")])
def test_client_maps_api_failures(monkeypatch, status, code):
    monkeypatch.setenv("TRIAGE_API_KEY", "test-key")
    monkeypatch.setattr(triage_client.requests, "get", lambda *a, **k: _Response(status, {}))

    with pytest.raises(triage_client.TriageError) as error:
        triage_client.find_sample(SHA)
    assert error.value.code == code


def test_client_needs_a_key_and_valid_identifiers(monkeypatch):
    monkeypatch.delenv("TRIAGE_API_KEY", raising=False)
    assert not triage_client.configured()
    for call, arg in ((triage_client.find_sample, SHA), (triage_client.find_sample, "nope"),
                      (triage_client.fetch_report, "../../etc")):
        with pytest.raises(triage_client.TriageError):
            call(arg)


def test_vendor_verdicts_keep_family_verdict_and_https_links_only():
    rows = vendor_verdicts({
        "ANY.RUN": [{"malware_family": "wannacry", "verdict": "Malicious activity",
                     "analysis_url": "https://app.any.run/tasks/3b429407"}],
        "Triage": {"malware_family": "wannacry", "score": "10", "link": "javascript:alert(1)"},
        "Empty": {"detection": None}, "Broken": "text"})

    assert rows == [
        {"vendor": "ANY.RUN", "family": "wannacry", "verdict": "Malicious activity", "score": "",
         "link": "https://app.any.run/tasks/3b429407"},
        {"vendor": "Triage", "family": "wannacry", "verdict": "", "score": "10", "link": ""}]
    assert vendor_verdicts(None) == []
