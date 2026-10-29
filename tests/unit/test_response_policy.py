from analysis_pipeline import run_pipeline
from ai_assistant import _build_context, _system_prompt
from response_policy import is_protected_destination


def test_wannacry_kill_switch_kept_as_evidence_not_block_rule(wannacry_report, wannacry_ioc):
    result, playbook = run_pipeline(wannacry_report, wannacry_ioc)
    assert result.network.domains
    assert any(o["type"] == "domain" and is_protected_destination(o["value"]) for o in result.research["evidence_bundle"]["observables"])
    assert not playbook.ioc_blocklist["domains"]
    assert not playbook.ioc_blocklist["urls"]
    assert not playbook.ioc_blocklist["ip_addresses"]
    commands = [c for a in playbook.actions for c in a.commands]
    assert not any('0.0.0.0 www.iuqerfsodp' in c or 'remoteip=104.17.220.11' in c for c in commands)
    assert any(o["role"] == "protective_service" for o in result.research["agent_analysis"]["findings"])
    assert result.research["response_exclusions"]


def test_protection_matches_exact_domain_not_lookalike():
    assert is_protected_destination('HTTP://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com/')
    assert is_protected_destination('http://iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com./path')
    assert not is_protected_destination('iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com.evil.example')


def test_assistant_sees_actual_artifacts_and_response_exclusions():
    context = _build_context({"processes": {"dropped": [{"name": "unique_artifact.exe"}], "registry": ["test-key"]},
                              "response_exclusions": [{"value": "protected.example", "reason": "do_not_block"}]})
    assert 'unique_artifact.exe' in context and 'protected.example' in context and 'test-key' in context
    assert 'không chặn domain/URL kill-switch' in _system_prompt()
