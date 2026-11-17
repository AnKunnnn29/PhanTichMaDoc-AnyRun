"""List samples that already have a public report on BOTH Any.Run and Triage.

For each malware family, MalwareBazaar is asked for recent samples of that signature,
then for each sample which sandboxes analysed it. A sample qualifies when its record
links an Any.Run task and a Triage report, so the two can be cross-checked on the same
file. Nothing is downloaded: only signature names and hashes are sent, and the output
is a list of links for the team to collect and label.

python -m ir_workspace.cli.find_samples --per-family 5 --output reports/evaluation/candidates
python -m ir_workspace.cli.find_samples --family Emotet=Heodo --family WannaCry=WannaCry
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import time
from pathlib import Path

from ir_workspace.integrations.hash_lookup import family_samples, lookup_hash
from ir_workspace.integrations.triage_report import SAMPLE_ID_RE

# Report name -> the signature MalwareBazaar uses for that family.
DEFAULT_FAMILIES = {"WannaCry": "WannaCry", "Emotet": "Heodo", "RedLine": "RedLineStealer",
                    "AgentTesla": "AgentTesla", "AsyncRAT": "AsyncRAT", "LockBit": "LockBit"}
ANYRUN_RE = re.compile(r"https://app\.any\.run/tasks/[0-9a-f-]{36}")
FIELDS = ["family", "signature", "sha256", "file_name", "file_type", "file_size", "first_seen", "dotnet",
          "anyrun_url", "triage_id", "triage_url", "other_vendors", "source_url"]
STOP = {"not_configured", "auth_error"}


def candidate(family: str, signature: str, sample: dict, lookup: dict) -> dict | None:
    """A sample both sandboxes analysed, or None."""
    vendors = {v["vendor"]: v for v in lookup.get("vendors") or []}
    anyrun = ANYRUN_RE.fullmatch(vendors.get("ANY.RUN", {}).get("link", ""))
    triage = SAMPLE_ID_RE.search(vendors.get("Triage", {}).get("link", ""))
    if not anyrun or not triage:
        return None
    return {"family": family, "signature": signature, **{k: sample[k] for k in FIELDS[2:8]},
            "anyrun_url": anyrun.group(), "triage_id": triage.group(),
            "triage_url": "https://tria.ge/" + triage.group(),
            "other_vendors": ";".join(sorted(v for v in vendors if v not in {"ANY.RUN", "Triage"})),
            "source_url": lookup.get("source_url", "")}


def find_candidates(families: dict, per_family: int, max_lookups: int, pause: float = 1.0, log=print) -> dict:
    found, notes = [], {}
    for family, signature in families.items():
        listing = family_samples(signature)
        if listing["status"] in STOP:
            raise SystemExit("MalwareBazaar: " + listing["status"] + " (cần MALWAREBAZAAR_AUTH_KEY hợp lệ trong .env)")
        # Native executables first: they are the ones the code-evidence step can disassemble.
        samples = sorted(listing["samples"], key=lambda s: (s["file_type"] not in {"exe", "dll"}, s["dotnet"]))
        kept, looked, status = 0, 0, listing["status"]
        for sample in samples[:max_lookups]:
            if kept >= per_family:
                break
            time.sleep(pause)
            lookup = lookup_hash(sample["sha256"])
            looked += 1
            if lookup["status"] in STOP | {"rate_limited"}:
                status = lookup["status"]
                break
            row = candidate(family, signature, sample, lookup) if lookup["status"] == "found" else None
            if row:
                found.append(row)
                kept += 1
        notes[family] = {"signature": signature, "listing_status": status, "listed": len(samples),
                         "looked_up": looked, "candidates": kept}
        log(f"{family}: {kept}/{per_family} mẫu đủ hai sandbox (đã tra {looked}/{len(samples)} mẫu, {status})")
    return {"candidates": found, "families": notes}


def main() -> None:
    parser = argparse.ArgumentParser(description="Find samples analysed by both Any.Run and Triage")
    parser.add_argument("--family", action="append", default=[], metavar="NAME=SIGNATURE",
                        help="Family to search; repeatable. Default: " + ", ".join(DEFAULT_FAMILIES))
    parser.add_argument("--per-family", type=int, default=5)
    parser.add_argument("--max-lookups", type=int, default=40, help="Hash lookups per family at most")
    parser.add_argument("--output", type=Path, default=Path("reports/evaluation/candidates"))
    args = parser.parse_args()
    from dotenv import load_dotenv
    load_dotenv()

    families = dict(item.split("=", 1) for item in args.family if "=" in item) or DEFAULT_FAMILIES
    result = find_candidates(families, max(1, args.per_family), max(1, args.max_lookups))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.with_suffix(".csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(result["candidates"])
    args.output.with_suffix(".json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"candidates": len(result["candidates"]), "csv": str(args.output.with_suffix(".csv").resolve())},
                     ensure_ascii=False))


if __name__ == "__main__":
    main()
