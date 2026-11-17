import pytest

from ir_workspace.analysis.code_evidence import (
    MAX_IMPORT_SITES, TRACKED_APIS, build_code_evidence, code_evidence_markdown, format_listing,
    import_vm_analysis, report_blocks, static_record)

SITE = {
    "api": "RegSetValueExA", "base_api": "RegSetValue", "library": "ADVAPI32.DLL",
    "function": "FUN_00401000", "function_entry": "00401000", "address": "0040102b",
    "instructions": [
        {"address": "00401020", "bytes": "68 c4 b0 40 00", "text": "PUSH 0x40b0c4",
         "comment": '"Software\\Microsoft\\Windows\\CurrentVersion\\Run"', "is_call": False},
        {"address": "0040102b", "bytes": "ff 15 00 a0 40 00", "text": "CALL dword ptr [0x0040a000]",
         "comment": "ADVAPI32.DLL::RegSetValueExA", "is_call": True},
    ],
}
SUMMARY = {"ghidra_version": "12.1.2", "language": "x86:LE:32:default", "executable_format": "Portable Executable (PE)",
           "call_counts": {"RegSetValueExA": 4, "CryptEncrypt": 2}, "call_sites": [SITE]}


def test_listing_marks_the_tracked_call_and_keeps_operand_comments():
    lines = format_listing(SITE).splitlines()

    assert lines[0].startswith("   00401020  68 c4 b0 40 00")
    assert "CurrentVersion" in lines[0]
    assert lines[1].startswith(">> 0040102b") and lines[1].endswith("; ADVAPI32.DLL::RegSetValueExA")


def test_call_sites_are_grouped_by_the_behaviour_their_api_implements():
    evidence = build_code_evidence(SUMMARY)

    by_id = {b["id"]: b for b in evidence["behaviors"]}
    assert by_id["persistence"]["apis"] == [{"name": "RegSetValueExA", "call_count": 4}]
    assert by_id["persistence"]["call_sites"][0]["listing"] == format_listing(SITE)
    # Counted by Ghidra but past the per-run cap on recorded sites: the API is still reported.
    assert by_id["data_encryption"]["apis"] == [{"name": "CryptEncrypt", "call_count": 2}]
    assert by_id["data_encryption"]["call_sites"] == []
    assert evidence["total_calls"] == 6 and evidence["total_call_sites"] == 1


def test_no_tracked_call_is_reported_as_a_limit_not_as_clean():
    evidence = build_code_evidence({"call_sites": [], "call_counts": {}})

    assert evidence["behaviors"] == []
    assert "pack" in evidence["note"]


def test_api_list_is_safe_as_one_command_line_argument():
    assert all(api.isalnum() for api in TRACKED_APIS)
    assert len(TRACKED_APIS) == len(set(TRACKED_APIS))


def _payload(sha256, observed):
    case = {"evidence_bundle": {"evidence": [{"type": "sha256", "value": "A" * 64}]}}
    analysis = {"triage": {"filename": "s.exe", "sha256": sha256, "md5": "", "size": 10},
                "ghidra": {"summary": SUMMARY}}
    return {"static_analysis": static_record(analysis, case),
            "impact_analysis": {"categories": [{"id": c, "title": "Cơ chế tự khởi động"} for c in observed]}}


def test_report_says_whether_the_sandbox_observed_the_behaviour_and_whether_the_sample_matches():
    matched = report_blocks(_payload("a" * 64, ["persistence"]))
    unmatched = report_blocks(_payload("b" * 64, []))

    persistence = next(b for b in matched["behaviors"] if b["title"].startswith("Cơ chế tự khởi động"))
    assert "Khớp nhóm tác động" in persistence["status"]
    assert "có trong hồ sơ" in matched["intro"][1]
    assert all("chưa phải hành vi đã xảy ra" in b["status"] for b in unmatched["behaviors"])
    assert unmatched["intro"][1].startswith("CẢNH BÁO")


def test_markdown_listing_cannot_be_closed_by_a_string_from_the_sample():
    payload = _payload("a" * 64, [])
    behaviors = payload["static_analysis"]["code_evidence"]["behaviors"]
    site = next(b for b in behaviors if b["id"] == "persistence")["call_sites"][0]
    site["listing"] = site["listing"] + "\n   00401030  90  NOP ; ```\n# injected"

    markdown = code_evidence_markdown(payload)

    assert markdown.count("```") == 2
    assert ">> 0040102b" in markdown


def test_reports_without_static_analysis_get_no_section():
    assert report_blocks({}) is None
    assert code_evidence_markdown({"static_analysis": {"code_evidence": {"behaviors": []}}}) == ""


def _vm_result(sha256="a" * 64):
    return {"analysis_origin": "vm_headless",
            "triage": {"filename": "sample.exe", "sha256": sha256, "md5": "d" * 32, "size": 4096},
            "ghidra": {"status": "ok", "summary": SUMMARY},
            "code_evidence": {"behaviors": [{"id": "forged", "call_sites": []}]}}


def _case(*sha):
    return {"evidence_bundle": {"evidence": [{"type": "sha256", "value": s} for s in sha]}}


def test_import_matches_hash_and_rebuilds_evidence_from_summary():
    record = import_vm_analysis(_vm_result("A" * 64), _case("a" * 64))

    assert record["hash_match"] is True
    assert record["analysis_origin"] == "vm_headless"
    # The forged code_evidence in the upload is ignored; it is rebuilt from the summary.
    assert {b["id"] for b in record["code_evidence"]["behaviors"]} == {"persistence", "data_encryption"}
    assert record["sha256"] == "a" * 64


def test_import_flags_a_sample_whose_hash_is_not_in_the_case():
    record = import_vm_analysis(_vm_result("b" * 64), _case("a" * 64))

    assert record["hash_match"] is False


@pytest.mark.parametrize("mutate", [
    lambda r: r.pop("triage"),
    lambda r: r.pop("ghidra"),
    lambda r: r["ghidra"].pop("summary"),
    lambda r: r["triage"].update(sha256="not-a-hash"),
])
def test_import_rejects_malformed_results(mutate):
    result = _vm_result()
    mutate(result)
    with pytest.raises(ValueError):
        import_vm_analysis(result, _case("a" * 64))


def test_import_caps_oversized_uploads():
    result = _vm_result()
    result["ghidra"]["summary"] = {
        "ghidra_version": "12.1.2", "call_counts": {"RegSetValueExA": 1},
        "call_sites": [dict(SITE, instructions=SITE["instructions"] * 200)] * (MAX_IMPORT_SITES + 50)}

    record = import_vm_analysis(result, _case("a" * 64))

    # Grouping still applies its own per-run caps; the point is the import does not choke.
    assert record["code_evidence"]["behaviors"]
