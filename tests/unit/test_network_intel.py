"""Per-destination network profiles: roles from sandbox facts, config C2 and abuse.ch intel."""
import copy

import pytest
import responses

import network_intel
from analysis_agent import _llm_priority
from analysis_pipeline import run_pipeline
from anyrun_public_report import _public_vue_data_to_anyrun_report
from evidence import collect_evidence
from network_intel import THREATFOX_URL, URLHAUS_HOST_URL, build_network_profiles, enrich_network_profiles

pytestmark = pytest.mark.unit
UUID = "4d6f6b46-fc90-40d9-ae47-55fe05b845b0"
WL, BAD, UNKNOWN = {"value": "whitelisted"}, {"value": "malicious"}, {"value": "unknown"}


def vue(connections=(), requests_=(), dns=(), config=None):
    return {"general": {"mainObject": {"value": "s.exe"}, "verdict": {"type": "2", "value": "Malicious activity"}, "tags": []},
            "meta": {"uuid": UUID},
            "networkActivity": {"connections": list(connections), "requests": list(requests_), "dns": list(dns), "threats": []},
            "malwareConfiguration": {"familiesMalconfs": config or []}}


def profiles_for(data):
    report = _public_vue_data_to_anyrun_report(copy.deepcopy(data), UUID)
    return {p["value"]: p for p in build_network_profiles(collect_evidence(report, {})).values()}, report


REDLINE_CONFIG = [{"family": "RedLine", "processesMalconfs": [{"process": {"pid": 6108, "image": "x" * 5000},
                   "malconfs": [{"config": {"C2": ["185.173.38.57:80"], "Botnet": "200k"}, "family": "RedLine", "processPID": 6108}]}]}]


def test_whitelisted_os_traffic_is_benign_and_not_blocked():
    data = vue(connections=[[5276, "MoUsoCoreWorker.exe", "172.215.188.232:443", "—", "MICROSOFT-CORP-MSN-AS-BLOCK", "US", WL],
                            [4, "System", "192.168.100.255:137", "—", "Not routed", "—", WL]],
               dns=[["www.bing.com", ["2.16.241.211"], WL]])
    profiles, report = profiles_for(data)
    assert profiles["172.215.188.232"]["role"] == "benign_infrastructure"
    assert "MoUsoCoreWorker.exe (PID 5276)" in profiles["172.215.188.232"]["summary"]
    assert profiles["192.168.100.255"]["role"] == "local_network"
    assert profiles["2.16.241.211"]["resolved_from"] == ["www.bing.com"]
    _, playbook = run_pipeline(report, {}, source="anyrun:public-report")
    assert playbook.ioc_blocklist["ip_addresses"] == [] and playbook.ioc_blocklist["domains"] == []


def test_destination_in_extracted_config_is_c2_and_the_only_block():
    data = vue(connections=[[6108, "s.exe", "185.173.38.57:80", "—", "Cloud assets LLC", "RU", BAD],
                            [2104, "svchost.exe", "40.127.240.158:443", "—", "MICROSOFT-CORP-MSN-AS-BLOCK", "IE", UNKNOWN]],
               config=REDLINE_CONFIG)
    profiles, report = profiles_for(data)
    c2 = profiles["185.173.38.57"]
    assert c2["role"] == "config_c2" and c2["severity"] == "critical" and c2["config_family"] == "RedLine"
    assert any(i.startswith("ev-") for i in c2["evidence_ids"])
    assert profiles["40.127.240.158"]["role"] == "unverified_destination"
    # The process block is dropped so the C2 setting is not truncated away.
    assert '"C2": ["185.173.38.57:80"]' in report["data"]["content"]["malwareConfig"][0]
    result, playbook = run_pipeline(report, {}, source="anyrun:public-report")
    assert playbook.ioc_blocklist["ip_addresses"] == ["185.173.38.57"]
    watched = next(x for x in result.research["response_exclusions"] if x["value"] == "40.127.240.158")
    assert "Theo dõi" in watched["reason"]
    stages = [s["stage"] for s in result.research["case_agent"]["assessment"]["behavior_chain"]]
    assert "command-and-control" in stages


def test_smb_to_many_hosts_reads_as_propagation():
    hosts = [[1572, "tasksche.exe", f"10.0.0.{n}:445", "—", "—", "—", UNKNOWN] for n in range(1, 7)]
    profiles, report = profiles_for(vue(connections=hosts))
    assert {p["role"] for p in profiles.values()} == {"smb_propagation"}
    assert profiles["10.0.0.1"]["smb_scan_peers"] == 6
    result, _ = run_pipeline(report, {}, source="anyrun:public-report")
    assert "lateral-movement" in [s["stage"] for s in result.research["case_agent"]["assessment"]["behavior_chain"]]


def test_kill_switch_dns_only_and_payload_download_roles():
    data = vue(dns=[["www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com", [], UNKNOWN], ["update.example.org", ["198.51.100.9"], UNKNOWN]],
               requests_=[[900, "s.exe", "GET", 200, "203.0.113.5:80", "http://203.0.113.5/stage2.exe", "NL", {"value": "binary"}, "88 Kb", UNKNOWN]])
    profiles, _ = profiles_for(data)
    assert profiles["www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"]["role"] == "kill_switch"
    assert profiles["update.example.org"]["role"] == "dns_only"
    assert profiles["http://203.0.113.5/stage2.exe"]["role"] == "payload_download"


@responses.activate
def test_intel_lookups_skip_benign_and_mark_known_c2(monkeypatch):
    monkeypatch.setenv("NETWORK_INTEL_LOOKUPS", "1")
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "test-placeholder")
    network_intel._cache.clear()
    responses.post(THREATFOX_URL, json={"query_status": "ok", "data": [
        {"id": 42, "malware_printable": "Emotet", "threat_type": "botnet_cc", "confidence_level": 100}]})
    responses.post(URLHAUS_HOST_URL, json={"query_status": "no_results"})
    data = vue(connections=[[1, "s.exe", "45.0.0.20:8080", "c2.example.net", "—", "—", UNKNOWN],
                            [2, "svchost.exe", "172.215.188.232:443", "—", "MICROSOFT", "US", WL]],
               dns=[["c2.example.net", ["45.0.0.20"], UNKNOWN]])
    report = _public_vue_data_to_anyrun_report(data, UUID)
    profiles = build_network_profiles(collect_evidence(report, {}))
    status = enrich_network_profiles(profiles)
    by_value = {p["value"]: p for p in profiles.values()}
    assert by_value["45.0.0.20"]["role"] == "known_c2"
    assert by_value["45.0.0.20"]["threat_intel"][0]["reference"] == "https://threatfox.abuse.ch/ioc/42/"
    assert by_value["172.215.188.232"]["threat_intel"] == [] and status["looked_up"] == 2
    assert all(c.request.headers["Auth-Key"] == "test-placeholder" for c in responses.calls)
    assert enrich_network_profiles(profiles, enabled=False)["enabled"] is False


@responses.activate
def test_intel_errors_are_counted_not_raised(monkeypatch):
    monkeypatch.setenv("NETWORK_INTEL_LOOKUPS", "1")
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "test-placeholder")
    network_intel._cache.clear()
    responses.post(THREATFOX_URL, status=503)
    profiles = build_network_profiles(collect_evidence(_public_vue_data_to_anyrun_report(
        vue(connections=[[1, "s.exe", "45.0.0.30:443", "—", "—", "—", UNKNOWN]]), UUID), {}))
    status = enrich_network_profiles(profiles)
    assert status["errors"] == 1 and next(iter(profiles.values()))["role"] == "unverified_destination"


def test_ioc_findings_use_profiles_and_llm_budget_prefers_network():
    data = vue(connections=[[6108, "s.exe", "185.173.38.57:80", "—", "Cloud assets LLC", "RU", BAD]], config=REDLINE_CONFIG)
    profiles, report = profiles_for(data)
    result, _ = run_pipeline(report, {}, source="anyrun:public-report")
    finding = next(f for f in result.research["agent_analysis"]["findings"] if f.get("network_role") == "config_c2")
    assert finding["severity"] == "critical" and "cấu hình mã độc" in finding["explanation"]
    by_id = result.research["network_profiles"]
    ip = next(o for o in result.research["evidence_bundle"]["observables"] if o["value"] == "185.173.38.57")
    assert _llm_priority(ip, by_id) == 0 and _llm_priority({"id": "x", "type": "sha256"}, by_id) == 5
