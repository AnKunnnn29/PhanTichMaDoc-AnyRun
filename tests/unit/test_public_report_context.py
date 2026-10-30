"""Public report normalisation keeps the context needed for per-IOC analysis."""
import copy

import pytest

from analysis_pipeline import build_behavior, run_pipeline
from anyrun_public_report import _public_vue_data_to_anyrun_report
from evidence import collect_evidence, validate_bundle
from validation import validate_report

pytestmark = pytest.mark.unit
UUID = "4a4f9f51-083f-47e7-9d1d-424bfcdbbeea"


def process(pid, cmd, path, parent, indicators=(), level=0):
    return {"pid": pid, "rowData": {"threatLevel": level, "values": [pid, cmd, path, list(indicators), parent],
                                    "information": {"values": ["admin", "", "HIGH", "", "0", ""]}}}


# Same cell layout as window.vueData on an ANY.RUN public report page.
VUE = {
    "general": {"mainObject": {"value": "sample.exe"}, "verdict": {"type": "2", "value": "Malicious activity"},
                "threats": [{"title": "Ransomware", "mainTag": "ransomware"}, {"title": "WannaCry", "mainTag": "wannacry"}],
                "tags": ["wannacry", "ransomware"], "indicators": ["autoStart"],
                "hashes": [{"key": "SHA256", "value": "a" * 64}]},
    "meta": {"uuid": UUID},
    "networkActivity": {
        "connections": [[1572, "sample.exe", "203.0.113.10:445", "—", "EXAMPLE-AS", "NL", {"value": "malicious", "type": 1}],
                        ["—", "—", "198.51.100.7:443", "c2.example.net", "—", "—", {"value": "unknown", "type": 0}]],
        "requests": [[1572, "sample.exe", "GET", 200, "198.51.100.7:80", "http://c2.example.net/a.bin", "US",
                      {"value": "binary", "type": 1}, "12 Kb", {"value": "malicious", "type": 1}]],
        "dns": [["c2.example.net", ["198.51.100.7", "198.51.100.8"], {"value": "malicious", "type": 1}]],
        "threats": [[1572, "sample.exe", {"value": "A Network Trojan was detected", "type": 1}, "ET EXPLOIT Possible ETERNALBLUE"]],
    },
    "behaviorActivities": [{"name": "MALICIOUS", "type": "2", "values": [
        {"name": "Deletes shadow copies", "values": ["cmd.exe (PID: 2000)"]},
        {"name": "WANNACRY has been found (auto)", "values": ["sample.exe (PID: 1572)"]}]}],
    "processes": {"processesValues": [
        process(1572, "sample.exe", r"C:\Users\admin\sample.exe", "explorer.exe", ["autoStart"], 2),
        process(2000, "cmd.exe /c vssadmin delete shadows /all /quiet", r"C:\Windows\System32\cmd.exe", "sample.exe"),
        process(3000, "svchost.exe -k netsvcs", r"C:\Windows\System32\svchost.exe", "services.exe"),
        process(3001, "conhost.exe", r"C:\Windows\System32\conhost.exe", "svchost.exe"),
        process(3002, "svchost.exe -k local", r"C:\Windows\System32\svchost.exe", "services.exe"),
    ]},
    "filesActivity": {"droppedFiles": [{"pid": "1572", "process": "sample.exe", "filename": r"C:\Users\admin\Desktop\a.docx.WNCRY",
                                        "md5": "b" * 32, "sha256": "c" * 64, "type": {}}]},
    "registryActivity": {"modificationEvents": [{"pid": 1572, "process": "sample.exe", "operation": "write",
                                                  "key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                                                  "name": "mssecsvc", "value": r"C:\Users\admin\tasksche.exe"}]},
    "malwareConfiguration": {"familiesMalconfs": [{"family": "WannaCry", "c2": ["c2.example.net"]}]},
}


@pytest.fixture
def report():
    return _public_vue_data_to_anyrun_report(copy.deepcopy(VUE), UUID)


def test_connections_keep_port_process_asn_country_and_reputation(report):
    network = report["data"]["content"]["network"]
    assert network["connections"][0] == {"ip": "203.0.113.10", "port": 445, "pid": 1572, "process": "sample.exe",
                                         "domain": "", "asn": "EXAMPLE-AS", "country": "NL", "reputation": "malicious"}
    assert network["connections"][1]["pid"] is None and network["connections"][1]["domain"] == "c2.example.net"
    request = network["httpRequests"][0]
    assert (request["pid"], request["method"], request["ip"], request["port"], request["reputation"]) == (1572, "GET", "198.51.100.7", 80, "malicious")


def test_dns_answers_stay_attached_to_their_domain(report):
    network = report["data"]["content"]["network"]
    assert network["dnsRequests"][0]["ips"] == ["198.51.100.7", "198.51.100.8"]
    assert "198.51.100.8" not in {c["ip"] for c in network["connections"]}
    bundle = collect_evidence(report, {})
    answer = next(e for e in bundle["evidence"] if e["value"] == "198.51.100.8")
    assert answer["context"]["relation"] == "dns_answer" and answer["context"]["domain"] == "c2.example.net"
    assert "198.51.100.8" in {o["value"] for o in bundle["observables"] if o["type"] == "ip"}


def test_alerts_behaviours_and_config_are_evidence_not_indicators(report):
    bundle = collect_evidence(report, {})
    validate_bundle(bundle)
    kinds = {e["type"] for e in bundle["evidence"]}
    assert {"alert", "behavior", "malware_config"} <= kinds
    assert not {"alert", "behavior", "malware_config"} & {o["type"] for o in bundle["observables"]}
    behavior = next(e for e in bundle["evidence"] if e["value"] == "Deletes shadow copies")
    assert behavior["context"]["processes"] == [{"name": "cmd.exe", "pid": 2000}]


def test_parent_is_linked_only_by_unique_name_and_labelled_inferred(report):
    processes = {p["pid"]: p for p in report["data"]["content"]["processes"]}
    assert processes[2000]["ppid"] == 1572 and processes[2000]["ppidBasis"] == "unique_parent_name"
    assert processes[3001]["ppid"] is None  # two svchost.exe processes: do not guess
    assert processes[2000]["cmd"].startswith("cmd.exe /c vssadmin")
    chain = build_behavior(collect_evidence(report, {}))
    parent = [r for r in chain["relations"] if r["relation"] == "parent_by_unique_name"]
    assert parent and all(r["assessment_status"] == "inferred" for r in parent)


def test_registry_threat_classes_and_full_pipeline(report):
    content = report["data"]["content"]
    assert content["registry"][0]["name"] == "mssecsvc" and content["registry"][0]["operation"] == "write"
    assert [t["title"] for t in content["threatClasses"]] == ["Ransomware", "WannaCry"]
    validate_report(report, {})
    result, playbook = run_pipeline(report, {})
    assert result.threat_info.threat_name == "WannaCry" and playbook.actions
    assert any(m["technique_id"] == "T1547.001" for m in result.research["mitre_mappings"])
