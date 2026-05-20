from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analyzer import (  # noqa: E402
    FileInfo,
    IOCData,
    MalwareAnalysisResult,
    NetworkActivity,
    ProcessActivity,
    ThreatInfo,
)
from demo_data import DEMO_IOC, DEMO_REPORT  # noqa: E402
from demo_data_redline import DEMO_REDLINE_IOC, DEMO_REDLINE_REPORT  # noqa: E402
from demo_data_wannacry import DEMO_WANNACRY_IOC, DEMO_WANNACRY_REPORT  # noqa: E402
from incident_response import IncidentAction, IncidentResponsePlaybook  # noqa: E402
import ml_engine as _ml_engine  # noqa: E402,F401


@pytest.fixture
def project_root() -> Path:
    return ROOT


@pytest.fixture
def emotet_report() -> dict:
    return copy.deepcopy(DEMO_REPORT)


@pytest.fixture
def emotet_ioc() -> dict:
    return copy.deepcopy(DEMO_IOC)


@pytest.fixture
def wannacry_report() -> dict:
    return copy.deepcopy(DEMO_WANNACRY_REPORT)


@pytest.fixture
def wannacry_ioc() -> dict:
    return copy.deepcopy(DEMO_WANNACRY_IOC)


@pytest.fixture
def redline_report() -> dict:
    return copy.deepcopy(DEMO_REDLINE_REPORT)


@pytest.fixture
def redline_ioc() -> dict:
    return copy.deepcopy(DEMO_REDLINE_IOC)


@pytest.fixture
def temp_output_dir(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture
def mock_anyrun_client():
    from anyrun_client import AnyRunClient

    return AnyRunClient("test-api-key", timeout=1)


@pytest.fixture
def flask_test_client(monkeypatch, tmp_path: Path):
    # app.py wraps stdout/stderr on win32 for normal console use. During pytest
    # capture that breaks the temporary capture streams. ml_engine/numpy are
    # already imported above under the real platform, so this only skips app.py's
    # console stream wrapping.
    monkeypatch.setattr(sys, "platform", "linux")
    import app as app_module

    monkeypatch.chdir(tmp_path)
    app_module._rate_buckets.clear()
    app_module.app.config.update(TESTING=True)
    with app_module.app.test_client() as client:
        yield client


@pytest.fixture
def sample_analysis_result() -> MalwareAnalysisResult:
    return MalwareAnalysisResult(
        task_uuid="test-task-uuid",
        file_info=FileInfo(
            name="invoice.doc",
            size=524288,
            md5="md5-test",
            sha1="sha1-test",
            sha256="sha256-test",
            file_type="MS Word Document",
            mime_type="application/msword",
        ),
        threat_info=ThreatInfo(
            verdict="Malicious",
            threat_level=3,
            threat_name="Emotet",
            tags=["emotet", "trojan"],
            mitre_techniques=[
                {"id": "T1566.001", "name": "Spearphishing Attachment", "tactic": "Initial Access"},
                {"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion"},
                {"id": "T1547.001", "name": "Registry Run Keys", "tactic": "Persistence"},
                {"id": "T1071.001", "name": "Web Protocols", "tactic": "Command and Control"},
            ],
        ),
        network=NetworkActivity(
            ip_addresses=["192.0.2.10", "198.51.100.20"],
            domains=["evil.example", "c2.example"],
            urls=["http://evil.example/payload"],
            http_requests=[{"method": "GET", "url": "http://evil.example/payload", "status": 200}],
            dns_queries=["evil.example"],
        ),
        processes=ProcessActivity(
            processes=[{"pid": 1234, "name": "winword.exe"}, {"pid": 4321, "name": "rundll32.exe"}],
            injected_processes=["rundll32.exe"],
            dropped_files=[{"name": "payload.dll", "sha256": "drop-sha256", "type": "DLL"}],
            registry_keys=["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"],
            mutexes=["Global\\TestMutex"],
        ),
        iocs=IOCData(
            ips=["192.0.2.10", "198.51.100.20"],
            domains=["evil.example", "c2.example"],
            urls=["http://evil.example/payload"],
            file_hashes=[{"sha256": "sha256-test"}, {"sha256": "drop-sha256"}],
            filenames=["invoice.doc", "payload.dll"],
        ),
        analysis_url="https://app.any.run/tasks/test-task-uuid",
        duration_seconds=120,
        os_env="Windows 10 x64",
        raw_report={},
    )


@pytest.fixture
def sample_playbook(sample_analysis_result: MalwareAnalysisResult) -> IncidentResponsePlaybook:
    return IncidentResponsePlaybook(
        malware_name=sample_analysis_result.threat_info.threat_name,
        severity="CRITICAL",
        threat_level=3,
        summary="Detected Emotet activity.",
        actions=[
            IncidentAction(
                priority=1,
                phase="Xác định (Identification)",
                category="Thu thập bằng chứng",
                title="Confirm sample",
                description="Confirm sample and preserve evidence.",
                commands=["Get-FileHash invoice.doc"],
                notes=["Store Any.Run report"],
            ),
            IncidentAction(
                priority=1,
                phase="Ngăn chặn (Containment)",
                category="Cô lập mạng",
                title="Block C2",
                description="Block C2 traffic.",
                commands=["netsh advfirewall firewall add rule name=Block_IR dir=out action=block remoteip=192.0.2.10"],
            ),
        ],
        ioc_blocklist={
            "ip_addresses": ["192.0.2.10", "198.51.100.20"],
            "domains": ["evil.example", "c2.example"],
            "urls": ["http://evil.example/payload"],
            "file_hashes": ["sha256-test", "drop-sha256"],
            "filenames": ["invoice.doc", "payload.dll"],
        },
        mitigation_summary="Isolate host, block IOCs, remove dropped files.",
        affected_os="Windows 10 x64",
    )
