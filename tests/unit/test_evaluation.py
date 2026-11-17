import json

import pytest

from ir_workspace.cli.evaluation import evaluate, load_manifest, score_extraction


def test_unlabelled_manifest_can_measure_timing_without_inventing_labels(tmp_path):
    (tmp_path / 'input.json').write_text(json.dumps({'data': {'content': {}}}))
    path = tmp_path / 'cases.json'
    path.write_text(json.dumps({'cases': [{'id': 'public', 'report_file': 'input.json'}]}))
    cases = load_manifest(path)
    assert cases[0]['expected'] is None
    assert evaluate(cases, tmp_path / 'out')['cases'][0]['extraction'] is None


@pytest.mark.parametrize('configs,runs', [([], 1), (['unknown'], 1), (['rules', 'rules'], 1),
                                         (['rules'], 0), (['rules'], -1), (['rules'], True)])
def test_comparison_rejects_invalid_requests(tmp_path, configs, runs):
    from ir_workspace.cli.evaluation import compare_configs
    with pytest.raises(ValueError):
        compare_configs([{'id': 'one'}], tmp_path, configs, runs)


def test_comparison_repeats_uncached_rules_and_records_stable_decisions(tmp_path, emotet_report):
    from ir_workspace.cli.evaluation import compare_configs
    result = compare_configs([{'id': 'one', 'report': emotet_report, 'iocs': {}}], tmp_path, ['rules'], 3)
    row = result['configs']['rules']
    assert row['case_runs'] == 3 and row['fallback_runs'] == 0
    assert row['stability']['one'] == {'runs': 3, 'distinct_decisions': 1, 'matching_pairs': 3,
                                      'pairs': 3, 'pair_agreement': 1}
    assert len(list(tmp_path.glob('rules/run_*/case_001.json'))) == 3
    assert not row['aggregate']['extraction']
    assert (tmp_path / 'comparison.md').exists()


def test_comparison_restores_provider_and_excludes_fallbacks_from_llm_results(monkeypatch, tmp_path):
    import os
    from ir_workspace.cli import evaluation as module
    monkeypatch.setenv('AGENT_PROVIDER', 'ollama')
    monkeypatch.setenv('AGENT_STRATEGY', 'original')
    calls = []
    def fake(cases, output):
        calls.append((os.environ['AGENT_PROVIDER'], os.environ['AGENT_STRATEGY']))
        output.mkdir(parents=True, exist_ok=True)
        complete = len(calls) % 2 == 1
        row = {'id': 'one', 'pipeline_ms': 1, 'llm_completed': complete,
               'decision_fingerprint': 'llm' if complete else 'rules', 'labels': {}}
        return {'settings': {}, 'cases': [row], 'aggregate': {}}
    monkeypatch.setattr(module, 'evaluate', fake)
    result = module.compare_configs([{'id': 'one'}], tmp_path, ['rules', 'single_shot', 'agent'], 2)
    assert calls == [('rules', 'agent')] * 2 + [('ollama', 'single_shot')] * 2 + [('ollama', 'agent')] * 2
    assert os.environ['AGENT_PROVIDER'] == 'ollama' and os.environ['AGENT_STRATEGY'] == 'original'
    for name in ['single_shot', 'agent']:
        row = result['configs'][name]
        assert row['fallback_runs'] == 1 and row['fallback_rate'] == .5
        assert row['completed_aggregate']['cases'] == 1
        assert row['completed_stability']['one']['pair_agreement'] is None


def test_configuration_is_restored_when_a_run_raises(monkeypatch, tmp_path):
    import os
    from ir_workspace.cli import evaluation as module
    monkeypatch.setenv('AGENT_PROVIDER', 'ollama')
    monkeypatch.delenv('AGENT_STRATEGY', raising=False)
    def fail(*args):
        raise RuntimeError('test')
    monkeypatch.setattr(module, 'evaluate', fail)
    with pytest.raises(RuntimeError):
        module.compare_configs([{'id': 'one'}], tmp_path, ['rules'], 1)
    assert os.environ['AGENT_PROVIDER'] == 'ollama' and 'AGENT_STRATEGY' not in os.environ


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
