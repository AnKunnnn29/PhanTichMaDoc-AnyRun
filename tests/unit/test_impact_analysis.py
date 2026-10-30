"""Impact facts: encrypted files, ransom notes, persistence, defence impairment, theft and decoded commands."""
import base64
import copy

import pytest

from analysis_pipeline import research_markdown, run_pipeline
from anyrun_public_report import _public_vue_data_to_anyrun_report
from evidence import collect_evidence
from impact_analysis import analyze_impact, decode_powershell
from network_intel import build_network_profiles

pytestmark = pytest.mark.unit
UUID = "4a4f9f51-083f-47e7-9d1d-424bfcdbbeea"
STARTUP = r"C:\Users\admin\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"


def proc(pid, cmd, name):
    return {"pid": pid, "rowData": {"threatLevel": 2, "values": [pid, cmd, rf"C:\Windows\System32\{name}", [], "explorer.exe"],
                                    "information": {"values": []}}}


def dropped(path, process="locker.exe", kind=""):
    return {"pid": "500", "process": process, "filename": path, "md5": "a" * 32, "sha256": "b" * 64, "type": {"value": kind}}


def encoded(text):
    return base64.b64encode(text.encode("utf-16-le")).decode()


RANSOM = {
    "general": {"mainObject": {"value": "locker.exe"}, "verdict": {"type": "2", "value": "Malicious activity"},
                "tags": ["ransomware", "wannacry"], "threats": [{"title": "Ransomware", "mainTag": "ransomware"}]},
    "meta": {"uuid": UUID},
    "processes": {"processesValues": [
        proc(600, rf'schtasks.exe /Create /F /TN "Updater" /SC ONLOGON /TR "{STARTUP}\updater.exe" /RL HIGHEST', "schtasks.exe"),
        proc(601, "powershell.exe -ExecutionPolicy Bypass Add-MpPreference -ExclusionPath 'C:\\Users\\admin\\AppData' -Force", "powershell.exe"),
        proc(602, "powershell.exe -EncodedCommand " + encoded("<#x#>Add-MpPreference -ExclusionPath @($env:UserProfile,$env:SystemDrive) -Force"), "powershell.exe"),
        proc(603, "cmd.exe /c vssadmin delete shadows /all /quiet", "cmd.exe"),
        proc(604, "icacls . /grant Everyone:F /T /C /Q", "icacls.exe"),
    ]},
    "filesActivity": {"droppedFiles":
        [dropped(rf"C:\Users\admin\Desktop\report{n}.docx.WNCRY") for n in range(6)]
        + [dropped(rf"C:\Users\admin\Pictures\photo{n}.jpg.WNCRY") for n in range(3)]
        + [dropped(rf"C:\Users\admin\Desktop\report{n}.docx.WNCRYT") for n in range(6)]
        + [dropped(r"C:\Users\admin\Desktop\@Please_Read_Me@.txt"), dropped(rf"{STARTUP}\updater.exe", kind="executable"),
           dropped(r"C:\Users\admin\AppData\Local\Temp\__PSScriptPolicyTest_abc.ps1", "powershell.exe")]},
    "behaviorActivities": [{"name": "MALICIOUS", "values": [{"name": "CRYPTOLOCKER has been found (auto)", "values": ["locker.exe (PID: 500)"]}]}],
    "networkActivity": {"connections": [], "requests": [], "dns": [], "threats": []},
}
STEALER = {
    "general": {"mainObject": {"value": "s.exe"}, "verdict": {"type": "2", "value": "Malicious activity"}, "tags": ["redline"]},
    "meta": {"uuid": UUID},
    "behaviorActivities": [{"name": "MALICIOUS", "values": [
        {"name": "Steals credentials from Web Browsers", "values": ["s.exe (PID: 6108)"]},
        {"name": "There is functionality for taking screenshot (YARA)", "values": ["s.exe (PID: 6108)"]}]}],
    "malwareConfiguration": {"familiesMalconfs": [{"family": "RedLine", "processesMalconfs": [
        {"malconfs": [{"config": {"C2": ["185.173.38.57:80"], "Botnet": "200k"}, "family": "RedLine", "processPID": 6108}]}]}]},
    "networkActivity": {"connections": [[6108, "s.exe", "185.173.38.57:80", "—", "Cloud assets LLC", "RU", {"value": "malicious"}]],
                        "requests": [], "dns": [], "threats": []},
}


def impact_for(data):
    report = _public_vue_data_to_anyrun_report(copy.deepcopy(data), UUID)
    bundle = collect_evidence(report, {})
    return analyze_impact(report, bundle, build_network_profiles(bundle)), bundle, report


def by_id(result):
    return {c["id"]: c for c in result["categories"]}


def test_encryption_counts_marker_files_types_folders_and_notes():
    result, bundle, _ = impact_for(RANSOM)
    enc = by_id(result)["data_encryption"]
    assert result["severity"] == "critical" and enc["severity"] == "critical"
    assert enc["facts"][0].startswith("9 tệp người dùng bị mã hóa") and ".WNCRY (9)" in enc["facts"][0]
    assert "WNCRYT" not in enc["facts"][0]  # temporary working copies are not counted twice
    assert ".docx (6)" in enc["facts"][1] and "Desktop (6)" in enc["facts"][2] and "@Please_Read_Me@.txt" in enc["facts"][3]
    evidence = {e["id"] for e in bundle["evidence"]}
    assert enc["evidence_ids"] and set(enc["evidence_ids"]) <= evidence


def test_recovery_persistence_and_defence_impairment_are_specific():
    result, bundle, _ = impact_for(RANSOM)
    cats = by_id(result)
    assert "vssadmin" in cats["recovery_inhibition"]["facts"][0]
    assert any('Scheduled task "Updater"' in f and "ONLOGON" in f and "quyền cao nhất" in f for f in cats["persistence"]["facts"])
    assert any("thư mục Startup" in f for f in cats["persistence"]["facts"])
    evasion = " ".join(cats["defense_impairment"]["facts"])
    assert r"C:\Users\admin\AppData" in evasion and "-Force" not in evasion
    assert "toàn bộ hồ sơ người dùng" in evasion and "Everyone" in evasion
    pid_602 = next(e["id"] for e in bundle["evidence"] if e["type"] == "process" and e["context"]["pid"] == 602)
    assert pid_602 in cats["defense_impairment"]["evidence_ids"]


def test_ransomware_signature_is_not_read_as_credential_theft_and_policy_test_files_ignored():
    cats = by_id(impact_for(RANSOM)[0])
    assert "credential_theft" not in cats
    assert not any("__PSScriptPolicyTest_" in f for f in cats["payload_drop"]["facts"])
    assert any("updater.exe" in f for f in cats["payload_drop"]["facts"])


def test_encoded_powershell_is_decoded():
    assert decode_powershell("powershell -enc " + encoded("Get-Process")) == "Get-Process"
    assert decode_powershell("powershell -Command Get-Process") == ""
    execution = by_id(impact_for(RANSOM)[0])["execution"]
    assert any("thực chất chạy: Add-MpPreference" in f for f in execution["facts"])


def test_stealer_theft_and_c2_categories():
    cats = by_id(impact_for(STEALER)[0])
    theft = " ".join(cats["credential_theft"]["facts"])
    assert "thông tin đăng nhập" in theft and "chụp màn hình" in theft and 'botnet "200k"' in theft
    assert cats["c2_communication"]["severity"] == "critical" and "185.173.38.57" in cats["c2_communication"]["facts"][0]


def test_pipeline_feeds_impact_into_agent_baseline_and_export():
    report = _public_vue_data_to_anyrun_report(copy.deepcopy(RANSOM), UUID)
    result, playbook = run_pipeline(report, {}, source="anyrun:public-report")
    case = result.research["case_agent"]["assessment"]
    assert case["impact"]["severity"] == "critical" and "bị mã hóa" in case["impact"]["summary"]
    assert "defense-impairment" in [s["stage"] for s in case["behavior_chain"]]
    payload = {**result.research, "playbook": {"actions": []}}
    assert "### Tác động và thiệt hại" in research_markdown(payload)


def test_clean_report_has_no_invented_impact():
    clean = {"general": {"mainObject": {"value": "ok.exe"}, "verdict": {"type": "0", "value": "No threats detected"}, "tags": []},
             "meta": {"uuid": UUID}}
    result = impact_for(clean)[0]
    assert result["categories"] == [] and result["severity"] == "info"
