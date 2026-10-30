from analysis_pipeline import run_pipeline
from dataclasses import asdict


def test_guidance_has_steps_verification_and_explicit_target_limit(wannacry_report, wannacry_ioc):
    _, playbook=run_pipeline(wannacry_report,wannacry_ioc,source='test')
    for action in playbook.actions:
        assert len(action.steps)>=3
        assert action.verification and action.rollback
        assert 'Chưa xác minh endpoint' in action.target_scope
        assert action.related_observations or action.blocked
        assert 'steps' in asdict(action)
    network=[a for a in playbook.actions if a.response_profile=='network']
    assert network
    assert any('kill-switch' in step for action in network for step in action.steps)


def test_clean_case_guidance_does_not_instruct_quarantine(sample_analysis_result):
    from analyzer import MalwareAnalysisResult,ThreatInfo
    from incident_response import IncidentResponseGenerator
    from operational_guidance import apply_guidance
    result=sample_analysis_result
    result.threat_info.verdict='Unknown'
    action=IncidentResponseGenerator().generate(result).actions[0]
    apply_guidance(action,result,{'evidence':[]})
    assert action.response_profile=='triage'
    assert all('quarantine' not in step.lower() for step in action.steps)
