import json
from pathlib import Path

import pytest

from ir_workspace.analysis.evaluation_metrics import aggregate, predictions, results_markdown, score_case, wilson
from ir_workspace.cli import find_samples
from ir_workspace.cli.evaluation import evaluate, load_manifest

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
SHA = "c34af1f1f238747d6839ce6857138e97d722443c4e2a794c072c236228ceaa07"


def _payload(source, family, impacts, techniques, blocked=(), sha256=SHA):
    return {"source": source, "case_id": "case-" + source, "file": {"sha256": sha256},
            "threat": {"threat_name": family}, "evidence_bundle": {"evidence": []},
            "impact_analysis": {"categories": [{"id": i, "title": i} for i in impacts]},
            "mitre_mappings": [{"technique_id": t} for t in techniques],
            "playbook": {"ioc_blocklist": {"ip_addresses": list(blocked), "domains": [], "urls": [],
                                           "file_hashes": ["not-a-destination"]}}}


def test_wilson_interval_is_wide_for_few_samples_and_empty_for_none():
    low, high = wilson(4, 5)
    assert low < 0.4 and high > 0.95
    assert wilson(0, 0) is None
    assert wilson(50, 100) == [0.404, 0.596]


def test_predictions_use_network_block_fields_only():
    found = predictions(_payload("import", "Wanna-Cry", ["persistence"], ["t1486"], blocked=["1.1.1.1"]))

    assert found == {"family": "wannacry", "impacts": {"persistence"}, "techniques": {"T1486"}, "blocked": {"1.1.1.1"}}


def test_case_is_scored_per_source_and_merged_with_agreement():
    primary = _payload("import", "WannaCry", ["data_encryption"], ["T1486"], blocked=["9.9.9.9"])
    second = _payload("triage:1", "wannacry", ["persistence"], ["T1486", "T1053.005"], blocked=["1.1.1.1"])
    case = {"reference_family": ["WannaCry", "wcry"], "expected_impacts": ["data_encryption", "persistence"],
            "expected_techniques": ["t1486", "T1053.005"], "expected_block": ["1.1.1.1"]}

    scored = score_case(case, primary, second)

    assert scored["family"] == {"primary": {"predicted": "wannacry", "correct": True},
                                "second": {"predicted": "wannacry", "correct": True}}
    # Each source alone misses one impact; together they find both.
    assert scored["impacts"]["primary"]["recall"] == scored["impacts"]["second"]["recall"] == 0.5
    assert scored["impacts"]["merged"]["recall"] == 1.0 and scored["impacts"]["merged"]["precision"] == 1.0
    assert scored["techniques"]["primary"]["false_negatives"] == ["T1053.005"]
    # Blocking: a false positive is a destination blocked wrongly, a false negative one that was missed.
    assert scored["blocked"]["primary"]["false_positives"] == ["9.9.9.9"]
    assert scored["blocked"]["primary"]["false_negatives"] == ["1.1.1.1"]
    assert scored["blocked"]["merged"]["precision"] == 0.5
    assert scored["agreement"]["attack_techniques"]["jaccard"] == 0.5 and scored["relation"] == "same_file"


def test_absent_labels_are_not_scored_and_unrelated_reports_are_reported():
    primary = _payload("import", "x", ["persistence"], [])
    assert score_case({}, primary) == {}
    assert score_case({"expected_block": []}, primary)["blocked"]["primary"]["fp"] == 0

    scored = score_case({}, primary, _payload("triage:1", "x", [], [], sha256="b" * 64))
    assert "không cùng một mẫu" in scored["agreement_error"] and "agreement" not in scored


def test_aggregate_micro_averages_and_reports_counts_with_intervals():
    def row(tp, fp, fn, correct):
        score = {"tp": tp, "fp": fp, "fn": fn}
        return {"extraction": score, "labels": {
            "family": {"primary": {"correct": correct}}, "impacts": {"primary": score, "merged": score},
            "agreement": {"family": {"title": "Họ mã độc", "jaccard": 1.0}, "c2": {"title": "C2", "jaccard": None}}}}

    summary = aggregate([row(3, 1, 0, True), row(1, 1, 2, False), {"labels": {}}])
    table = results_markdown(summary)

    assert summary["cases"] == 3
    assert summary["family"]["primary"] == {"correct": 1, "total": 2, "accuracy": 0.5, "ci95": wilson(1, 2)}
    assert summary["impacts"]["primary"]["precision"] == 0.667 and summary["impacts"]["primary"]["cases"] == 2
    assert summary["impacts"]["primary"]["recall_ci95"] == wilson(4, 6)
    assert "second" not in summary["impacts"] and summary["techniques"] == {}
    # A dimension neither source observed has no agreement to average.
    assert summary["agreement"] == {"family": {"title": "Họ mã độc", "cases": 2, "mean_jaccard": 1.0}}
    assert "| Nhóm tác động | P 67% [" in table and "| Họ mã độc đúng | 1/2 = 50% [" in table
    assert "không phải độ chính xác" in table


def test_manifest_with_a_triage_second_source_produces_scores_and_a_results_table(tmp_path, emotet_report):
    overview = json.loads((FIXTURES / "triage_overview.json").read_text(encoding="utf-8"))
    overview["sample"]["sha256"] = emotet_report["data"]["content"]["mainObject"]["hashes"]["sha256"]
    (tmp_path / "anyrun.json").write_text(json.dumps(emotet_report), encoding="utf-8")
    (tmp_path / "overview.json").write_text(json.dumps(overview), encoding="utf-8")
    (tmp_path / "dynamic.json").write_text((FIXTURES / "triage_dynamic.json").read_text(encoding="utf-8"), encoding="utf-8")
    case = {"id": "emotet-1", "report_file": "anyrun.json", "second_report_file": "overview.json",
            "second_dynamic_file": "dynamic.json", "label_reviewer": "Reviewer", "expected": [],
            "reference_family": "Emotet", "expected_impacts": ["persistence"], "expected_techniques": ["T1053.005"],
            "expected_block": []}
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"cases": [case]}), encoding="utf-8")

    summary = evaluate(load_manifest(manifest), tmp_path / "out")
    labels = summary["cases"][0]["labels"]

    assert labels["relation"] == "same_file" and set(labels["impacts"]) == {"primary", "second", "merged"}
    assert labels["family"]["primary"]["correct"] is True and labels["family"]["second"]["correct"] is False
    assert summary["aggregate"]["techniques"]["second"]["tp"] == 1
    assert (tmp_path / "out" / "case_001_second.json").exists()
    assert "| Chiều đối chiếu |" in (tmp_path / "out" / "results.md").read_text(encoding="utf-8")

    case["expected_block"] = "1.1.1.1"
    manifest.write_text(json.dumps({"cases": [case]}), encoding="utf-8")
    with pytest.raises(ValueError):
        load_manifest(manifest)


def test_candidates_need_both_sandboxes_and_stop_on_rate_limits(monkeypatch):
    def vendors(*names):
        links = {"ANY.RUN": "https://app.any.run/tasks/3b429407-e9be-4a57-bb33-9b673e4852da",
                 "Triage": "https://tria.ge/reports/260317-xlg6lafz9j/", "CAPE": "https://www.capesandbox.com/a/1/"}
        return [{"vendor": n, "family": "", "verdict": "", "score": "", "link": links[n]} for n in names]

    samples = [{"sha256": f"{i:064x}", "file_name": f"s{i}.exe", "file_type": kind, "file_size": 10,
                "first_seen": "", "dotnet": dotnet}
               for i, (kind, dotnet) in enumerate([("zip", False), ("exe", True), ("exe", False), ("exe", False)])]
    answers = {samples[2]["sha256"]: vendors("ANY.RUN", "Triage", "CAPE"), samples[3]["sha256"]: vendors("ANY.RUN"),
               samples[1]["sha256"]: vendors("Triage")}
    order = []

    def lookup(sha):
        order.append(sha)
        return {"status": "found", "vendors": answers.get(sha, []), "source_url": "https://bazaar.abuse.ch/sample/" + sha}

    monkeypatch.setattr(find_samples, "family_samples", lambda signature: {"status": "ok", "samples": samples})
    monkeypatch.setattr(find_samples, "lookup_hash", lookup)

    result = find_samples.find_candidates({"WannaCry": "WannaCry"}, 5, 10, pause=0, log=lambda _: None)

    # Native executables are tried first, .NET next, containers last.
    assert order[0] == samples[2]["sha256"] and order[-1] == samples[0]["sha256"]
    assert [c["sha256"] for c in result["candidates"]] == [samples[2]["sha256"]]
    assert result["candidates"][0]["triage_id"] == "260317-xlg6lafz9j"
    assert result["candidates"][0]["other_vendors"] == "CAPE"
    assert result["families"]["WannaCry"] == {"signature": "WannaCry", "listing_status": "ok", "listed": 4,
                                              "looked_up": 4, "candidates": 1}

    monkeypatch.setattr(find_samples, "lookup_hash", lambda sha: {"status": "rate_limited"})
    limited = find_samples.find_candidates({"WannaCry": "WannaCry"}, 5, 10, pause=0, log=lambda _: None)
    assert limited["families"]["WannaCry"]["looked_up"] == 1
    assert limited["families"]["WannaCry"]["listing_status"] == "rate_limited"
    monkeypatch.setattr(find_samples, "family_samples", lambda signature: {"status": "auth_error", "samples": []})
    with pytest.raises(SystemExit):
        find_samples.find_candidates({"WannaCry": "WannaCry"}, 5, 10, pause=0, log=lambda _: None)
