from pathlib import Path

from ghidra_analyzer import build_ir_enrichment, lightweight_static_triage


def test_static_triage_does_not_treat_dll_names_as_domains(tmp_path: Path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ user32.dll WININET.dll KERNEL32.dll http://evil.example/a VirtualAlloc")

    triage = lightweight_static_triage(str(sample))

    assert triage["domains"] == ["evil.example"]
    assert "VirtualAlloc" in triage["suspicious_apis"]


def test_ir_enrichment_explains_static_not_dynamic():
    enrichment = build_ir_enrichment(
        {"entropy": 4.3, "suspicious_apis": ["VirtualAlloc"], "urls": [], "ips": [], "domains": [], "registry": []},
        {"status": "ok", "summary": {"function_count": 10, "suspicious_imports": ["GetProcAddress"]}},
    )

    assert enrichment["analysis_type"] == "static"
    assert enrichment["dynamic_analysis"] is False
    assert enrichment["malicious_assessment"]["verdict"] == "Có dấu hiệu nghi vấn"
    assert "Ghidra không thực thi file" in enrichment["evidence_note"]
