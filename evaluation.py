"""Reproducible extraction evaluation; semantic quality requires human labels.

python evaluation.py --demo
python evaluation.py --manifest evaluation_manifest.json --output reports/evaluation
"""
from __future__ import annotations

import argparse
import csv
import json
import platform
import statistics
import time
from pathlib import Path

from analysis_agent import agent_settings
from analysis_pipeline import run_pipeline
from evidence import digest, normalize, validate_bundle
from reporter import _report_payload

TYPES = {"ip", "domain", "url", "md5", "sha1", "sha256", "file", "process", "registry", "mutex"}


def score_extraction(expected, predicted):
    """Micro counts over normalized (type,value) sets, including negative cases."""
    def pairs(rows):
        result = set()
        for row in rows:
            kind = row["type"]
            if kind not in TYPES:
                raise ValueError(f"Unsupported observable type: {kind}")
            value, valid = normalize(kind, row["value"])
            if not valid:
                raise ValueError(f"Invalid label: {kind} {row['value']}")
            result.add((kind, value))
        return result
    expected, predicted = pairs(expected), pairs(predicted)
    tp, fp, fn = len(expected & predicted), len(predicted - expected), len(expected - predicted)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None
    return {"tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "f1": f1,
            "false_positives": sorted(predicted - expected), "false_negatives": sorted(expected - predicted)}


def demo_cases():
    from demo_data import DEMO_REPORT, DEMO_IOC
    from demo_data_wannacry import DEMO_WANNACRY_REPORT, DEMO_WANNACRY_IOC
    from demo_data_redline import DEMO_REDLINE_REPORT, DEMO_REDLINE_IOC
    # No automatic ground truth generated from the parser under evaluation.
    return [{"id": name, "report": report, "iocs": iocs, "expected": None,
             "dataset_kind": "synthetic_smoke_only"}
            for name, report, iocs in [("emotet", DEMO_REPORT, DEMO_IOC),
                ("wannacry", DEMO_WANNACRY_REPORT, DEMO_WANNACRY_IOC),
                ("redline", DEMO_REDLINE_REPORT, DEMO_REDLINE_IOC)]]


def load_manifest(path):
    path = Path(path).resolve()
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data.get("cases"), list) or not data["cases"]:
        raise ValueError("Manifest requires a non-empty cases list")
    cases = []
    ids = set()
    for row in data["cases"]:
        if row["id"] in ids:
            raise ValueError("Case IDs must be unique")
        ids.add(row["id"])
        if not row.get("label_reviewer") or not isinstance(row.get("expected"), list):
            raise ValueError("Each case requires label_reviewer and an exhaustive expected list")
        def read(name):
            return json.loads((path.parent / row[name]).read_text(encoding="utf-8-sig"))
        cases.append({**row, "report": read("report_file"),
                      "iocs": read("ioc_file") if row.get("ioc_file") else {}})
    return cases


def evaluate(cases, output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    rows, rubric = [], []
    for index, case in enumerate(cases):
        started = time.perf_counter()
        result, playbook = run_pipeline(case["report"], case["iocs"], source="evaluation")
        elapsed = round((time.perf_counter() - started) * 1000, 3)
        payload = _report_payload(result, playbook)
        validate_bundle(payload["evidence_bundle"])
        # Numeric filenames prevent untrusted manifest IDs becoming filesystem paths.
        name = f"case_{index + 1:03d}.json"
        (output / name).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        predicted = [o for o in payload["evidence_bundle"]["observables"] if o["valid"] and o["type"] in TYPES]
        expected = case.get("expected")
        score = score_extraction(expected, predicted) if expected is not None else None
        row = {"id": case["id"], "dataset_kind": case.get("dataset_kind", "unspecified"),
               "input_sha256": digest([case["report"], case["iocs"]]), "output_file": name,
               "pipeline_ms": elapsed, "cache_used": False, "agent_mode": payload["agent_analysis"]["mode"],
               "observable_count": len(predicted), "reference_integrity": True,
               "extraction": score, "semantic_accuracy": "requires_independent_review"}
        if expected is not None:
            row["by_type"] = {kind: score_extraction([o for o in expected if o["type"] == kind],
                                                     [o for o in predicted if o["type"] == kind]) for kind in sorted(TYPES)}
            row["label_reviewer"] = case["label_reviewer"]
        rows.append(row)
        rubric.append({"case_id": case["id"], "reviewer": "", "ioc_role_1_5": "",
                       "behavior_reasoning_1_5": "", "mitre_support_1_5": "", "response_safety_1_5": "",
                       "unsupported_claim_count": "", "manual_baseline_minutes": "", "notes": ""})
    summary = {"schema_version": "1.0", "python": platform.python_version(), "settings": agent_settings(),
               "run_method": "single uncached run per case; not a statistical speedup study",
               "median_pipeline_ms": statistics.median(r["pipeline_ms"] for r in rows), "cases": rows,
               "limitations": ["Synthetic demos have no independent labels and no accuracy score.",
                   "Reference integrity verifies provenance, not correctness of conclusions.",
                   "Label expected must include ALL supported observables, including filenames and processes.",
                   "Report precision/recall separately from human-rated semantic quality."]}
    (output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    with (output / "manual_review.csv").open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rubric[0]))
        writer.writeheader()
        writer.writerows(rubric)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--demo", action="store_true")
    group.add_argument("--manifest", type=Path)
    parser.add_argument("--output", type=Path, default=Path("reports/evaluation"))
    args = parser.parse_args()
    summary = evaluate(demo_cases() if args.demo else load_manifest(args.manifest), args.output)
    print(json.dumps({"cases": len(summary["cases"]), "output": str(args.output.resolve()),
                      "median_pipeline_ms": summary["median_pipeline_ms"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
