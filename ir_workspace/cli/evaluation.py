"""Reproducible extraction evaluation; semantic quality requires human labels.

python evaluation.py --demo
python evaluation.py --manifest evaluation_manifest.json --output reports/evaluation
python evaluation.py --manifest evaluation_manifest.json --configs rules,single_shot,agent --runs 3
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import platform
import statistics
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from ir_workspace.ai.analysis_agent import agent_settings
from ir_workspace.analysis.analysis_pipeline import run_pipeline
from ir_workspace.analysis.evaluation_metrics import LABEL_KEYS, aggregate, results_markdown, score_case, wilson
from ir_workspace.analysis.evidence import digest, normalize, validate_bundle
from ir_workspace.integrations.triage_report import is_triage_report, triage_to_report
from ir_workspace.reporting.reporter import _report_payload
from ir_workspace.paths import PROJECT_ROOT

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
    from ir_workspace.demo.demo_data import DEMO_REPORT, DEMO_IOC
    from ir_workspace.demo.demo_data_wannacry import DEMO_WANNACRY_REPORT, DEMO_WANNACRY_IOC
    from ir_workspace.demo.demo_data_redline import DEMO_REDLINE_REPORT, DEMO_REDLINE_IOC
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
        expected = row.get("expected")
        if expected is not None and not isinstance(expected, list):
            raise ValueError("expected must be an exhaustive list or null for an unlabelled case")
        has_labels = expected is not None or any(key in row for key in (*LABEL_KEYS, "reference_family"))
        if has_labels and not row.get("label_reviewer"):
            raise ValueError("Labelled cases require label_reviewer")
        for key in LABEL_KEYS:
            if key in row and not (isinstance(row[key], list) and all(isinstance(v, str) for v in row[key])):
                raise ValueError(f"{key} must be a list of strings")
        def read(name):
            return json.loads((path.parent / row[name]).read_text(encoding="utf-8-sig"))
        case = {**row, "expected": expected, "report": read("report_file"), "iocs": read("ioc_file") if row.get("ioc_file") else {}}
        if row.get("second_report_file"):
            # A second sandbox's report of the same sample; a Triage overview is converted first.
            second = read("second_report_file")
            if is_triage_report(second):
                dynamic = [read("second_dynamic_file")] if row.get("second_dynamic_file") else []
                second = triage_to_report(second, dynamic)
            case["second_report"] = second
        cases.append(case)
    return cases


# The three ways the same report can be analysed. Only the environment differs between them.
CONFIGS = {"rules": {"AGENT_PROVIDER": "rules", "AGENT_STRATEGY": "agent"},
           "single_shot": {"AGENT_STRATEGY": "single_shot"},
           "agent": {"AGENT_STRATEGY": "agent"}}
CONFIG_TITLES = {"rules": "Chỉ luật", "single_shot": "LLM một lượt", "agent": "AI Agent"}


def decision_fingerprint(payload):
    """Compare structured conclusions, excluding prose, random case IDs and timings."""
    actions = {a["id"]: a["title"] for a in payload.get("playbook", {}).get("actions", [])}
    assessment = payload.get("case_agent", {}).get("assessment", {})
    return digest({
        "ioc": sorted((f["ioc_id"], f["role"], f["severity"], f["assessment_status"])
                      for f in payload.get("agent_analysis", {}).get("findings", [])),
        "impact": assessment.get("impact", {}).get("severity"),
        "techniques": sorted({m for stage in assessment.get("behavior_chain", []) for m in stage.get("mitre", [])}),
        "actions": sorted((actions.get(a["action_id"], a["action_id"]), a["decision"], a.get("priority"))
                          for a in assessment.get("action_plan", [])),
    })


def _stability(rows):
    by_case = {}
    for row in rows:
        by_case.setdefault(row["id"], []).append(row["decision_fingerprint"])
    result = {}
    for case_id, fingerprints in by_case.items():
        pairs = len(fingerprints) * (len(fingerprints) - 1) // 2
        equal = sum(a == b for i, a in enumerate(fingerprints) for b in fingerprints[i + 1:])
        result[case_id] = {"runs": len(fingerprints), "distinct_decisions": len(set(fingerprints)),
                           "matching_pairs": equal, "pairs": pairs,
                           "pair_agreement": equal / pairs if pairs else None}
    return result


@contextmanager
def _configured(name: str):
    previous = {key: os.environ.get(key) for key in ("AGENT_PROVIDER", "AGENT_STRATEGY")}
    os.environ.update(CONFIGS[name])
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def compare_configs(cases, output, configs, runs=1):
    """Run every case `runs` times under each configuration and put timing, stability and scores side by side."""
    output = Path(output)
    unknown = [name for name in configs if name not in CONFIGS]
    if unknown or not configs or len(set(configs)) != len(configs):
        raise ValueError("Cấu hình hợp lệ: " + ", ".join(CONFIGS))
    if not cases or len({c["id"] for c in cases}) != len(cases):
        raise ValueError("Cần ít nhất một mẫu và ID mẫu không trùng nhau")
    if not isinstance(runs, int) or isinstance(runs, bool) or runs < 1:
        raise ValueError("Số lần chạy phải là số nguyên dương")
    if os.getenv("AGENT_PROVIDER", "rules").strip().lower() == "rules" and any(name != "rules" for name in configs):
        raise ValueError("Cần đặt AGENT_PROVIDER là một mô hình (deepseek, gemini, openai, ollama) để chạy cấu hình có LLM")
    comparison = {"created_at": datetime.now(timezone.utc).isoformat(), "runs_per_case": runs,
                  "cases": len(cases), "configs": {},
                  "limitations": ["Repeated runs of the same case are not independent samples; intervals are descriptive.",
                      "Stability compares structured decisions, not wording or semantic correctness.",
                      "Extraction, impact, ATT&CK and blocklist scores measure shared rules, not LLM reasoning.",
                      "LLM quality requires independent review of findings and case assessments."]}
    for name in configs:
        with _configured(name):
            summaries = [evaluate(cases, output / name / f"run_{n + 1}") for n in range(runs)]
        rows = [row for summary in summaries for row in summary["cases"]]
        times = [row["pipeline_ms"] for row in rows]
        # A run that fell back to the rules did not measure the model.
        fallbacks = sum(not row["llm_completed"] for row in rows) if name != "rules" else 0
        valid_rows = rows if name == "rules" else [row for row in rows if row["llm_completed"]]
        comparison["configs"][name] = {
            "title": CONFIG_TITLES[name], "settings": summaries[0]["settings"], "case_runs": len(rows),
            "median_pipeline_ms": statistics.median(times), "mean_pipeline_ms": round(statistics.fmean(times), 3),
            "max_pipeline_ms": max(times), "stdev_pipeline_ms": round(statistics.stdev(times), 3) if len(times) > 1 else None,
            "fallback_runs": fallbacks, "llm_completed_runs": sum(row["llm_completed"] for row in rows),
            "fallback_rate": round(fallbacks / len(rows), 3), "fallback_ci95": wilson(fallbacks, len(rows)),
            "aggregate": aggregate(rows), "completed_aggregate": aggregate(valid_rows),
            "run_aggregates": [s["aggregate"] for s in summaries],
            "stability": _stability(rows), "completed_stability": _stability(valid_rows)}
    lines = ["| Cấu hình | Số lần chạy | Trung vị (ms) | Trung bình (ms) | Lớn nhất (ms) | Phải dùng kết quả luật |",
             "|---|---|---|---|---|---|"]
    for name, item in comparison["configs"].items():
        low, high = item["fallback_ci95"]
        lines.append(f"| {item['title']} | {item['case_runs']} | {item['median_pipeline_ms']:.0f} | "
                     f"{item['mean_pipeline_ms']:.0f} | {item['max_pipeline_ms']:.0f} | "
                     f"{item['fallback_runs']}/{item['case_runs']} = {item['fallback_rate']:.0%} [{low:.0%}–{high:.0%}] |")
    for name, item in comparison["configs"].items():
        lines += ["", f"### {item['title']}", "", results_markdown(item["aggregate"])]
        lines += ["", "Độ ổn định của quyết định có cấu trúc (gồm cả lượt dự phòng):", "",
                  "| Mẫu | Số lượt | Kết quả khác nhau | Cặp trùng / tổng cặp |", "|---|---|---|---|"]
        for case_id, stable in item["stability"].items():
            label = str(case_id).replace("|", "&#124;").replace("\n", " ").replace("\r", " ")
            lines.append(f"| {label} | {stable['runs']} | {stable['distinct_decisions']} | "
                         f"{stable['matching_pairs']}/{stable['pairs']} |")
        if name != "rules":
            lines += ["", f"Lượt hoàn tất cả hai phần LLM: {item['llm_completed_runs']}/{item['case_runs']}. "
                      "Chỉ dùng các lượt này để chấm chất lượng LLM; xem completed_stability và completed_aggregate trong JSON."]
    lines += ["", "Các chỉ số trích xuất, tác động, ATT&CK và danh sách chặn đo phần luật dùng chung. "
              "Cần chấm thủ công phần diễn giải và đề xuất của LLM. Mẫu chưa có nhãn không có điểm chính xác. "
              "Lượt lặp cùng mẫu không phải mẫu độc lập; khoảng tin cậy chỉ mang tính mô tả."]
    (output / "comparison.json").write_text(json.dumps(comparison, ensure_ascii=False, indent=2), encoding="utf-8")
    (output / "comparison.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return comparison


def evaluate(cases, output):
    if not cases:
        raise ValueError("Cần ít nhất một mẫu để đánh giá")
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
               "case_agent_mode": payload["case_agent"]["mode"],
               "observable_count": len(predicted), "reference_integrity": True,
               "decision_fingerprint": decision_fingerprint(payload),
               "llm_completed": payload["case_agent"]["mode"] == "llm" and
                   (payload["agent_analysis"]["mode"] == "llm" or not predicted),
               "extraction": score, "semantic_accuracy": "requires_independent_review"}
        if expected is not None:
            row["by_type"] = {kind: score_extraction([o for o in expected if o["type"] == kind],
                                                     [o for o in predicted if o["type"] == kind]) for kind in sorted(TYPES)}
            row["label_reviewer"] = case["label_reviewer"]
        second = None
        if case.get("second_report"):
            sandbox = (case["second_report"].get("data", {}).get("analysis", {}).get("sandbox") or {})
            source = "triage:" + str(sandbox.get("sample_id", "")) if sandbox.get("name") == "Triage" else "second"
            second = _report_payload(*run_pipeline(case["second_report"], {}, source=source))
            (output / f"case_{index + 1:03d}_second.json").write_text(
                json.dumps(second, ensure_ascii=False, indent=2), encoding="utf-8")
        row["labels"] = score_case(case, payload, second)
        rows.append(row)
        rubric.append({"case_id": case["id"], "reviewer": "", "ioc_role_1_5": "",
                       "behavior_reasoning_1_5": "", "mitre_support_1_5": "", "response_safety_1_5": "",
                       "unsupported_claim_count": "", "manual_baseline_minutes": "", "notes": ""})
    summary = {"schema_version": "1.1", "created_at": datetime.now(timezone.utc).isoformat(),
               "python": platform.python_version(), "settings": agent_settings(),
               "run_method": "single uncached run per case; not a statistical speedup study",
               "median_pipeline_ms": statistics.median(r["pipeline_ms"] for r in rows), "cases": rows,
               "limitations": ["Synthetic demos have no independent labels and no accuracy score.",
                   "Reference integrity verifies provenance, not correctness of conclusions.",
                   "Label expected must include ALL supported observables, including filenames and processes.",
                   "Report precision/recall separately from human-rated semantic quality.",
                   "Agreement between two sandboxes is not accuracy; it is reported in its own table."]}
    summary["aggregate"] = aggregate(rows)
    (output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    (output / "results.md").write_text(results_markdown(summary["aggregate"]), encoding="utf-8")
    with (output / "manual_review.csv").open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rubric[0]))
        writer.writeheader()
        writer.writerows(rubric)
    return summary


def main():
    from dotenv import load_dotenv
    load_dotenv(PROJECT_ROOT / ".env", override=False)
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--demo", action="store_true")
    group.add_argument("--manifest", type=Path)
    parser.add_argument("--output", type=Path, default=Path("reports/evaluation"))
    parser.add_argument("--configs", default="", help="So sánh cấu hình, ví dụ: rules,single_shot,agent")
    parser.add_argument("--runs", type=int, default=1, help="Số lần chạy mỗi mẫu cho mỗi cấu hình")
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs phải lớn hơn 0")
    cases = demo_cases() if args.demo else load_manifest(args.manifest)
    if args.configs or args.runs > 1:
        names = [c.strip() for c in args.configs.split(",") if c.strip()]
        if not names:
            settings = agent_settings()
            names = ["rules" if settings["provider"] == "rules" else settings["strategy"]]
        comparison = compare_configs(cases, args.output, names, args.runs)
        print(json.dumps({name: {k: item[k] for k in ("case_runs", "median_pipeline_ms", "fallback_rate")}
                          for name, item in comparison["configs"].items()}, ensure_ascii=False))
        return
    summary = evaluate(cases, args.output)
    print(json.dumps({"cases": len(summary["cases"]), "output": str(args.output.resolve()),
                      "median_pipeline_ms": summary["median_pipeline_ms"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
