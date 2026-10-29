import json

import pytest

from evaluation import evaluate, load_manifest, score_extraction


def test_precision_recall_counts_and_normalization():
    expected = [{"type": "domain", "value": "EXAMPLE.COM."}, {"type": "ip", "value": "192.0.2.1"}]
    predicted = [{"type": "domain", "value": "example.com"}, {"type": "ip", "value": "192.0.2.2"}]
    result = score_extraction(expected, predicted)
    assert (result["tp"], result["fp"], result["fn"]) == (1, 1, 1)
    assert result["precision"] == result["recall"] == result["f1"] == .5
    assert score_extraction([], [predicted[0]])["fp"] == 1
    assert score_extraction([], [])["f1"] is None
    with pytest.raises(ValueError):
        score_extraction([{"type": "ip", "value": "invalid"}], [])


def test_manifest_labels_and_negative_case_evaluation(tmp_path):
    (tmp_path / "input.json").write_text(json.dumps({"data": {"content": {}}}))
    manifest = {"cases": [{"id": "negative", "report_file": "input.json", "label_reviewer": "Independent reviewer",
                           "expected": [], "dataset_kind": "synthetic_negative"}]}
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    summary = evaluate(load_manifest(path), tmp_path / "out")
    assert summary["cases"][0]["extraction"]["fp"] == 0
    assert summary["cases"][0]["reference_integrity"]
    assert (tmp_path / "out/manual_review.csv").exists()
    del manifest["cases"][0]["label_reviewer"]
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        load_manifest(path)


def test_unlabelled_case_never_claims_accuracy(tmp_path, emotet_report):
    summary = evaluate([{"id": "demo", "report": emotet_report, "iocs": {}, "expected": None}], tmp_path)
    assert summary["cases"][0]["extraction"] is None
    assert summary["cases"][0]["cache_used"] is False
