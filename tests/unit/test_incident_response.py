from __future__ import annotations

import pytest

from incident_response import IncidentResponseGenerator

pytestmark = pytest.mark.unit


class TestPlaybookGeneration:
    @pytest.mark.parametrize(
        ("threat_level", "expected_severity"),
        [(0, "LOW"), (1, "MEDIUM"), (2, "HIGH"), (3, "CRITICAL"), (4, "CRITICAL")],
    )
    def test_severity_mapping(self, sample_analysis_result, threat_level, expected_severity):
        sample_analysis_result.threat_info.threat_level = threat_level

        playbook = IncidentResponseGenerator().generate(sample_analysis_result)

        assert playbook.severity == expected_severity

    def test_malicious_sample_has_high_or_critical_severity(self, sample_analysis_result):
        sample_analysis_result.threat_info.threat_level = 2

        playbook = IncidentResponseGenerator().generate(sample_analysis_result)

        assert playbook.severity in {"HIGH", "CRITICAL"}
        assert playbook.malware_name == "Emotet"
        assert "Emotet" in playbook.summary


class TestNISTPhases:
    def test_all_required_nist_phases_are_present(self, sample_analysis_result):
        playbook = IncidentResponseGenerator().generate(sample_analysis_result)
        phase_text = "\n".join(action.phase for action in playbook.actions)

        for expected in ["Identification", "Containment", "Eradication", "Recovery", "Lessons Learned"]:
            assert expected in phase_text


class TestMITREActions:
    def test_network_iocs_create_firewall_block_actions(self, sample_analysis_result):
        playbook = IncidentResponseGenerator().generate(sample_analysis_result)

        commands = "\n".join(command for action in playbook.actions for command in action.commands)
        assert "netsh advfirewall firewall add rule" in commands
        assert "192.0.2.10" in commands

    def test_injected_processes_create_taskkill_actions(self, sample_analysis_result):
        playbook = IncidentResponseGenerator().generate(sample_analysis_result)

        commands = "\n".join(command for action in playbook.actions for command in action.commands)
        assert 'taskkill /F /IM "rundll32.exe" /T' in commands

    def test_t1486_creates_ransomware_critical_action(self, sample_analysis_result):
        sample_analysis_result.threat_info.mitre_techniques.append(
            {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"}
        )

        playbook = IncidentResponseGenerator().generate(sample_analysis_result)

        ransomware_actions = [action for action in playbook.actions if "RANSOMWARE" in action.title]
        assert ransomware_actions
        assert ransomware_actions[0].priority == 1

    def test_wannacry_recovery_requires_reimage_and_clean_backup(self, sample_analysis_result):
        sample_analysis_result.threat_info.threat_name = "WannaCry"
        sample_analysis_result.threat_info.tags = ["wannacry", "ransomware"]
        sample_analysis_result.threat_info.mitre_techniques.append(
            {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"}
        )

        playbook = IncidentResponseGenerator().generate(sample_analysis_result)
        combined = "\n".join(
            [playbook.mitigation_summary]
            + [action.title for action in playbook.actions]
            + [action.description for action in playbook.actions]
            + [note for action in playbook.actions for note in action.notes]
            + [command for action in playbook.actions for command in action.commands]
        ).lower()

        assert "reimage" in combined
        assert "backup" in combined
        assert "không tin cậy" in combined
        assert "smb1protocol" in combined

    def test_stealer_playbook_prioritizes_session_revocation(self, sample_analysis_result):
        sample_analysis_result.threat_info.threat_name = "RedLine Stealer"
        sample_analysis_result.threat_info.tags = ["redline", "stealer"]
        sample_analysis_result.threat_info.mitre_techniques.append(
            {"id": "T1555.003", "name": "Credentials from Web Browsers", "tactic": "Credential Access"}
        )

        playbook = IncidentResponseGenerator().generate(sample_analysis_result)
        combined = "\n".join(
            [playbook.mitigation_summary]
            + [action.title for action in playbook.actions]
            + [action.description for action in playbook.actions]
            + [note for action in playbook.actions for note in action.notes]
            + [command for action in playbook.actions for command in action.commands]
        ).lower()

        assert "revoke" in combined
        assert "token" in combined
        assert "reset mật khẩu" in combined
        assert "browser cache" in combined

    def test_botnet_with_persistence_recommends_rebuild_not_only_cleanup(self, sample_analysis_result):
        sample_analysis_result.threat_info.threat_name = "Emotet"
        sample_analysis_result.threat_info.tags = ["emotet", "botnet"]

        playbook = IncidentResponseGenerator().generate(sample_analysis_result)
        combined = "\n".join(
            [playbook.mitigation_summary]
            + [action.title for action in playbook.actions]
            + [action.description for action in playbook.actions]
            + [note for action in playbook.actions for note in action.notes]
        ).lower()

        assert "rebuild" in combined or "reimage" in combined
        assert "không chỉ xóa artifact" in combined
        assert "edr" in combined

    def test_t1566_creates_email_quarantine_action(self, sample_analysis_result):
        playbook = IncidentResponseGenerator().generate(sample_analysis_result)

        assert any("Phishing" in action.title and "quarantine" in action.title for action in playbook.actions)

    def test_t1055_creates_memory_dump_action(self, sample_analysis_result):
        playbook = IncidentResponseGenerator().generate(sample_analysis_result)

        commands = "\n".join(command for action in playbook.actions for command in action.commands)
        assert "volatility" in commands
        assert "procdump.exe" in commands

    def test_registry_persistence_keys_create_cleanup_actions(self, sample_analysis_result):
        playbook = IncidentResponseGenerator().generate(sample_analysis_result)

        commands = "\n".join(command for action in playbook.actions for command in action.commands)
        assert "reg delete" in commands
        assert "CurrentVersion\\Run\\Updater" in commands

    def test_empty_network_data_still_generates_playbook(self, sample_analysis_result):
        sample_analysis_result.network.ip_addresses = []
        sample_analysis_result.network.domains = []
        sample_analysis_result.iocs.ips = []
        sample_analysis_result.iocs.domains = []

        playbook = IncidentResponseGenerator().generate(sample_analysis_result)

        assert playbook.actions
        assert playbook.ioc_blocklist["ip_addresses"] == []

    def test_playbook_includes_operational_owner_sla_and_evidence(self, sample_analysis_result):
        playbook = IncidentResponseGenerator().generate(sample_analysis_result)

        assert all(action.owner for action in playbook.actions)
        assert all(action.sla for action in playbook.actions)
        assert all(action.evidence_required for action in playbook.actions)
        assert {action.status for action in playbook.actions} == {"pending"}

    def test_playbook_includes_timeline_scope_hunting_and_scoring(self, sample_analysis_result):
        playbook = IncidentResponseGenerator().generate(sample_analysis_result)

        assert playbook.severity_score["score"] > 0
        assert playbook.severity_score["recommended_severity"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        assert any(item["stage"] == "Command and Control" for item in playbook.timeline)
        assert any("IOC" in item["question"] for item in playbook.scope_hunting)
        assert any("Scope" in action.category for action in playbook.actions)


class TestIOCBlocklist:
    def test_ioc_blocklist_contains_unique_analysis_iocs(self, sample_analysis_result):
        playbook = IncidentResponseGenerator().generate(sample_analysis_result)

        assert playbook.ioc_blocklist["ip_addresses"] == sample_analysis_result.iocs.ips
        assert playbook.ioc_blocklist["domains"] == sample_analysis_result.iocs.domains
        assert "sha256-test" in playbook.ioc_blocklist["file_hashes"]
        assert "drop-sha256" in playbook.ioc_blocklist["file_hashes"]

    def test_actions_are_sorted_by_priority(self, sample_analysis_result):
        playbook = IncidentResponseGenerator().generate(sample_analysis_result)
        priorities = [action.priority for action in playbook.actions]

        assert priorities == sorted(priorities)

    def test_unknown_threat_level_maps_to_unknown(self, sample_analysis_result):
        sample_analysis_result.threat_info.threat_level = 99

        playbook = IncidentResponseGenerator().generate(sample_analysis_result)

        assert playbook.severity == "UNKNOWN"

    @pytest.mark.parametrize(
        ("size", "expected"),
        [(10, "10 B"), (2048, "2.0 KB"), (3 * 1024 * 1024, "3.0 MB")],
    )
    def test_format_file_size(self, size, expected):
        assert IncidentResponseGenerator._fmt_size(size) == expected
