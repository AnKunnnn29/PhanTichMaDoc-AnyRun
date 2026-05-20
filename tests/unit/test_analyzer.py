from __future__ import annotations

import copy

import pytest

from analyzer import MalwareAnalyzer

pytestmark = pytest.mark.unit


class TestMalwareAnalyzerParsing:
    @pytest.mark.parametrize(
        ("report_fixture", "ioc_fixture", "expected_name"),
        [
            ("emotet_report", "emotet_ioc", "Emotet"),
            ("wannacry_report", "wannacry_ioc", "WannaCry"),
            ("redline_report", "redline_ioc", "RedLine Stealer"),
        ],
    )
    def test_malware_family_detection(self, request, report_fixture, ioc_fixture, expected_name):
        result = MalwareAnalyzer().parse_report(
            request.getfixturevalue(report_fixture),
            request.getfixturevalue(ioc_fixture),
        )

        assert result.threat_info.threat_name == expected_name

    def test_wannacry_threat_level_is_high_or_critical(self, wannacry_report, wannacry_ioc):
        result = MalwareAnalyzer().parse_report(wannacry_report, wannacry_ioc)

        assert result.threat_info.threat_name == "WannaCry"
        assert result.threat_info.threat_level >= 3
        assert result.threat_info.verdict == "Malicious"

    def test_missing_fields_parse_with_defaults(self):
        result = MalwareAnalyzer().parse_report({}, {})

        assert result.task_uuid == "unknown"
        assert result.file_info is None
        assert result.threat_info.threat_level == 0
        assert result.network.ip_addresses == []
        assert result.iocs.file_hashes == []


class TestMITREParsing:
    @pytest.mark.parametrize("count", [0, 1, 5, 20])
    def test_parse_mitre_extracts_all_technique_ids(self, emotet_report, count):
        report = copy.deepcopy(emotet_report)
        techniques = [
            {"id": f"T{1000 + idx}", "name": f"Technique {idx}", "tactic": "Discovery"} for idx in range(count)
        ]
        report["data"]["content"]["mitre"] = techniques

        result = MalwareAnalyzer().parse_report(report, {})

        assert [item["id"] for item in result.threat_info.mitre_techniques] == [item["id"] for item in techniques]


class TestNetworkParsing:
    def test_parse_network_deduplicates_ips_domains_and_urls(self, emotet_report):
        content = copy.deepcopy(emotet_report["data"]["content"])
        content["network"]["connections"].append({"ip": "185.220.101.45"})
        content["network"]["httpRequests"].append(copy.deepcopy(content["network"]["httpRequests"][0]))
        content["network"]["dnsRequests"].append({"domain": "malicious-c2.ru"})

        network = MalwareAnalyzer()._parse_network(content)

        assert network.ip_addresses.count("185.220.101.45") == 1
        assert network.domains.count("malicious-c2.ru") == 1
        assert network.urls.count("http://malicious-c2.ru/update/check") == 1
        assert network.dns_queries.count("malicious-c2.ru") == 2

    def test_parse_network_handles_empty_network(self):
        network = MalwareAnalyzer()._parse_network({})

        assert network.ip_addresses == []
        assert network.domains == []
        assert network.urls == []


class TestProcessParsing:
    def test_parse_processes_identifies_injected_processes(self, emotet_report):
        processes = MalwareAnalyzer()._parse_processes(emotet_report["data"]["content"])

        assert "rundll32.exe" in processes.injected_processes
        assert "svchost.exe" in processes.injected_processes

    def test_parse_processes_extracts_dropped_files_registry_and_mutexes(self, emotet_report):
        processes = MalwareAnalyzer()._parse_processes(emotet_report["data"]["content"])

        assert any(item["name"].endswith("payload.dll") for item in processes.dropped_files)
        assert any(item["sha256"] for item in processes.dropped_files)
        assert any("CurrentVersion\\Run" in key for key in processes.registry_keys)
        assert "Global\\EmoteMutex_v2" in processes.mutexes

    def test_parse_processes_deduplicates_registry_and_mutexes(self, emotet_report):
        content = copy.deepcopy(emotet_report["data"]["content"])
        content["registry"].append(copy.deepcopy(content["registry"][0]))
        content["synchronization"].append(copy.deepcopy(content["synchronization"][0]))

        processes = MalwareAnalyzer()._parse_processes(content)

        assert len(processes.registry_keys) == len(set(processes.registry_keys))
        assert len(processes.mutexes) == len(set(processes.mutexes))


class TestIOCParsing:
    def test_parse_iocs_accepts_list_response_and_deduplicates(self, emotet_report):
        content = emotet_report["data"]["content"]
        ioc_list = [
            {"type": "ip", "value": "192.0.2.1"},
            {"type": "ip", "value": "192.0.2.1"},
            {"type": "domain", "value": "example.test"},
            {"type": "url", "value": "http://example.test/a"},
            {"type": "sha256", "value": "hash-value"},
            {"type": "filename", "value": "payload.exe"},
        ]

        iocs = MalwareAnalyzer()._parse_iocs(ioc_list, content)

        assert iocs.ips.count("192.0.2.1") == 1
        assert "example.test" in iocs.domains
        assert "http://example.test/a" in iocs.urls
        assert {"sha256": "hash-value"} in iocs.file_hashes
        assert "payload.exe" in iocs.filenames

    def test_parse_iocs_derives_from_report_when_ioc_endpoint_empty(self, emotet_report):
        iocs = MalwareAnalyzer()._parse_iocs({}, emotet_report["data"]["content"])

        assert "185.220.101.45" in iocs.ips
        assert "malicious-c2.ru" in iocs.domains
        assert "Invoice_2024_Q4.doc" in iocs.filenames
        assert any("sha256" in item for item in iocs.file_hashes)


class TestFamilyDetection:
    def test_generic_threat_name_is_replaced_with_specific_family(self, wannacry_report):
        report = copy.deepcopy(wannacry_report)
        report["data"]["content"]["scores"]["specs"]["knownThreat"] = "Ransomware"
        report["data"]["content"]["scores"]["verdict"]["threatLevel"] = 1

        result = MalwareAnalyzer().parse_report(report, {})

        assert result.threat_info.threat_name == "WannaCry"
        assert result.threat_info.threat_level == 3

    @pytest.mark.parametrize(
        ("filename", "expected"),
        [
            ("agenttesla_invoice.exe", "AgentTesla"),
            ("lumma_stealer_payload.exe", "Lumma"),
            ("qbot_loader.exe", "QakBot"),
        ],
    )
    def test_alias_heuristics_detect_family_from_filename(self, emotet_report, filename, expected):
        report = copy.deepcopy(emotet_report)
        report["data"]["analysis"]["tags"] = []
        report["data"]["content"]["scores"]["specs"]["knownThreat"] = "malware"
        report["data"]["content"]["mainObject"]["filename"] = filename

        result = MalwareAnalyzer().parse_report(report, {})

        assert result.threat_info.threat_name == expected

    def test_file_info_is_parsed(self, emotet_report, emotet_ioc):
        result = MalwareAnalyzer().parse_report(emotet_report, emotet_ioc)

        assert result.file_info is not None
        assert result.file_info.name == "Invoice_2024_Q4.doc"
        assert result.file_info.sha256
