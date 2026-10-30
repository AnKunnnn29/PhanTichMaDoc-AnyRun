"""Case-specific remediation: exact targets, verify-first queries, and no blocking of benign traffic."""
import copy

import pytest

from analysis_pipeline import run_pipeline
from anyrun_public_report import _public_vue_data_to_anyrun_report
from incident_response import IncidentAction
from remediation import merge_actions
from test_impact_analysis import RANSOM, STEALER, UUID

pytestmark = pytest.mark.unit


def plan(data):
    _, playbook = run_pipeline(_public_vue_data_to_anyrun_report(copy.deepcopy(data), UUID), {}, source="anyrun:public-report")
    return playbook.actions


def case(actions, words):
    return next(a for a in actions if a.origin == "case_specific" and words in a.title)


def test_ransomware_plan_targets_the_exact_artifacts():
    actions = plan(RANSOM)
    isolate = case(actions, "Cô lập máy")
    assert any('FileName endswith ".WNCRY"' in c for c in isolate.commands)
    assert "Chưa xác minh endpoint" in isolate.target_scope and isolate.preconditions
    restore = case(actions, "Khôi phục dữ liệu")
    assert any("vssadmin" in step for step in restore.steps)
    persistence = case(actions, "tự khởi động")
    assert "schtasks /Delete /TN 'Updater' /F" in persistence.commands
    assert persistence.commands.index("schtasks /Query /TN 'Updater' /V /FO LIST > task_0.txt") < persistence.commands.index("schtasks /Delete /TN 'Updater' /F")
    defender = case(actions, "loại trừ Defender")
    assert r"Remove-MpPreference -ExclusionPath 'C:\Users\admin\AppData'" in defender.commands
    assert "Remove-MpPreference -ExclusionPath $env:UserProfile" in defender.commands
    assert case(actions, "Reimage").priority == 1


def test_case_actions_replace_templates_and_are_reviewable():
    actions = plan(RANSOM)
    specific = [a for a in actions if a.origin == "case_specific"]
    assert specific and all(a.id.startswith("action-") and a.evidence_ids and not a.blocked for a in specific)
    covered = {a.response_profile for a in specific}
    assert not [a for a in actions if a.origin == "template" and a.response_profile in covered - {"lessons"}]
    assert all(len(a.steps) >= 3 and a.verification and a.rollback for a in specific)
    assert not any("<đường_dẫn_file>" in c for a in specific for c in a.commands)


def test_stealer_plan_blocks_only_config_c2_and_resets_credentials():
    actions = plan(STEALER)
    block = case(actions, "Chặn 1 đích")
    netsh = [c for c in block.commands if c.startswith("netsh")]
    assert netsh == ['netsh advfirewall firewall add rule name="IR_block_185.173.38.57" dir=out action=block remoteip=185.173.38.57']
    assert any("DeviceNetworkEvents" in c and "185.173.38.57" in c for c in block.commands)
    theft = case(actions, "Thu hồi phiên")
    assert any("Revoke-MgUserSignInSession" in c for c in theft.commands)
    assert not case(actions, "Reimage").blocked


def test_whitelisted_traffic_is_never_blocked():
    data = copy.deepcopy(STEALER)
    data["networkActivity"]["connections"] = [[1, "svchost.exe", "172.215.188.232:443", "—", "MICROSOFT", "US", {"value": "whitelisted"}]]
    data["malwareConfiguration"] = {"familiesMalconfs": []}
    actions = plan(data)
    assert case(actions, "Không chặn mạng")
    assert not any("action=block" in c for a in actions for c in a.commands)


def test_demo_wannacry_keeps_kill_switch_reachable(wannacry_report, wannacry_ioc):
    _, playbook = run_pipeline(wannacry_report, wannacry_ioc, source="test")
    keep = case(playbook.actions, "kill-switch")
    assert any("Resolve-DnsName" in c for c in keep.commands)
    assert not any("iuqerfsodp" in c and c.startswith("netsh") for a in playbook.actions for c in a.commands)


def test_merge_keeps_uncovered_templates_labelled():
    template = IncidentAction(priority=2, phase="Phục hồi (Recovery)", category="x", title="t", description="d")
    template.response_profile = "recover"
    specific = IncidentAction(priority=1, phase="Ngăn chặn (Containment)", category="y", title="s", description="d")
    specific.response_profile, specific.origin = "network", "case_specific"
    merged = merge_actions([template], [specific])
    assert [a.title for a in merged] == ["s", "t"] and merged[1].origin == "template"
