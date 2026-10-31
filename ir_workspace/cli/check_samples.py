"""Check local AES ZIP samples in memory; never execute, extract or upload them.

python -m ir_workspace.cli.check_samples --samples-dir "../Samples Malware"
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

from ir_workspace.integrations.ghidra_analyzer import static_triage_bytes, build_ir_enrichment

MAX_BYTES = 64 * 1024 * 1024


def check_samples(folder: Path) -> dict:
    try:
        import pyzipper
        from pypdf import PdfReader
    except ImportError as exc:
        raise SystemExit("Install optional dependencies: python -m pip install -r requirements-samples.txt") from exc
    folder = folder.resolve(strict=True)
    password = (folder / "password.txt").read_text(encoding="utf-8-sig").strip().encode("utf-8")
    results = []
    archives = sorted(folder.rglob("*.zip"))
    if not archives:
        raise ValueError("No ZIP samples found")
    for archive in archives:
        record = {"family_folder": archive.parent.name, "archive": archive.name,
                  "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(), "members": []}
        try:
            if archive.stat().st_size > MAX_BYTES:
                raise ValueError("Archive exceeds 64 MiB")
            with pyzipper.AESZipFile(archive) as package:
                members = [member for member in package.infolist() if not member.is_dir()]
                if len(members) > 20 or sum(member.file_size for member in members) > MAX_BYTES:
                    raise ValueError("Expanded sample exceeds local inspection limits")
                for member in members:
                    with package.open(member, pwd=password) as stream:
                        data = stream.read(MAX_BYTES + 1)
                    if len(data) > MAX_BYTES:
                        raise ValueError("Member exceeds 64 MiB")
                    triage = static_triage_bytes(data, member.filename)
                    if triage["file_type"] != "PE executable":
                        raise ValueError("Expected a Windows PE payload")
                    enrichment = build_ir_enrichment(triage, {"status": "not_run", "reason": "memory_only_inspection"})
                    record["members"].append({"name": member.filename, "size": triage["size"],
                        "file_type": triage["file_type"], "sha256": triage["sha256"],
                        "entropy": round(triage["entropy"], 4),
                        "counts": {key: len(triage[key]) for key in ("strings", "urls", "ips", "domains", "registry", "suspicious_apis")},
                        "assessment": enrichment["malicious_assessment"],
                        "dynamic_analysis": enrichment["dynamic_analysis"]})
            pdfs = sorted(archive.parent.glob("*.pdf"))
            record["pdf_reports"] = []
            for pdf in pdfs:
                reader = PdfReader(pdf)
                text = reader.pages[0].extract_text() or ""
                match = re.search(r"SHA256:\s*([a-fA-F0-9]{64})", text)
                reported_hash = match.group(1).lower() if match else None
                reference = "container" if reported_hash == record["archive_sha256"] else "payload" if any(reported_hash == item["sha256"] for item in record["members"]) else "unmatched_or_missing"
                record["pdf_reports"].append({"filename": pdf.name, "pages": len(reader.pages),
                    "reported_sha256": reported_hash, "hash_refers_to": reference,
                    "content_scope": "first-page metadata only; not imported as structured sandbox evidence"})
            record["status"] = "passed"
        except Exception as exc:
            record["status"] = "failed"
            record["error"] = type(exc).__name__ + ": " + str(exc)
        results.append(record)
    return {"mode": "static_memory_only", "execution": False, "uploads": False,
            "ghidra_headless": "not_run", "cases": results,
            "limitations": ["Static strings are candidates, not confirmed malicious IOCs.",
                "No malware detection accuracy is measured without independent labels.",
                "PDF metadata is checked; PDF sandbox reports are not supported structured imports."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples-dir", required=True, type=Path)
    parser.add_argument("--output", type=Path, default=Path("reports/sample-check.json"))
    args = parser.parse_args()
    result = check_samples(args.samples_dir)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(args.output.resolve()), "cases": [{"family": row["family_folder"], "status": row["status"]} for row in result["cases"]]}, ensure_ascii=False))
    raise SystemExit(0 if all(case["status"] == "passed" for case in result["cases"]) else 1)


if __name__ == "__main__":
    main()
