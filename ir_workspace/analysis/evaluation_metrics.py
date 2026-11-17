"""Score pipeline output against reviewer labels, per source and with two sources merged.

Every rate carries its counts and a 95% Wilson interval: with a few dozen samples a bare
percentage hides how wide the uncertainty is. Agreement between two sandboxes is kept
apart from accuracy, because two sources seeing the same thing does not make it true.
"""
from __future__ import annotations

import math
import re

from ir_workspace.analysis.sandbox_compare import compare_payloads

BLOCK_FIELDS = ("ip_addresses", "domains", "urls")
LABEL_KEYS = ("expected_impacts", "expected_techniques", "expected_block")
SOURCES = ("primary", "second", "merged")


def wilson(successes: int, total: int, z: float = 1.96):
    """95% Wilson score interval for a proportion; None when there is nothing to count."""
    if not total:
        return None
    p = successes / total
    denom = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denom
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return [round(max(0.0, centre - half), 3), round(min(1.0, centre + half), 3)]


def rates(tp: int, fp: int, fn: int) -> dict:
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None
    return {"tp": tp, "fp": fp, "fn": fn,
            "precision": None if precision is None else round(precision, 3), "precision_ci95": wilson(tp, tp + fp),
            "recall": None if recall is None else round(recall, 3), "recall_ci95": wilson(tp, tp + fn),
            "f1": None if f1 is None else round(f1, 3)}


def score_sets(expected, predicted) -> dict:
    expected, predicted = set(expected), set(predicted)
    return {**rates(len(expected & predicted), len(predicted - expected), len(expected - predicted)),
            "false_positives": sorted(predicted - expected), "false_negatives": sorted(expected - predicted)}


def _family(value) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def predictions(payload: dict) -> dict:
    """What the pipeline concluded, in the same vocabulary as the labels."""
    blocklist = (payload.get("playbook") or {}).get("ioc_blocklist") or {}
    return {
        "family": _family((payload.get("threat") or {}).get("threat_name")),
        "impacts": {c["id"] for c in (payload.get("impact_analysis") or {}).get("categories", []) if c.get("id")},
        "techniques": {str(m.get("technique_id", "")).upper() for m in payload.get("mitre_mappings") or []
                       if m.get("technique_id")},
        "blocked": {str(v).lower() for field in BLOCK_FIELDS for v in blocklist.get(field) or []},
    }


def score_case(case: dict, payload: dict, second: dict | None = None) -> dict:
    """Scores for the labels a case carries. A label that is absent is not scored, never assumed empty."""
    found = {"primary": predictions(payload)}
    if second is not None:
        found["second"] = predictions(second)
        union = {k: found["primary"][k] | found["second"][k] for k in ("impacts", "techniques", "blocked")}
        found["merged"] = {"family": found["primary"]["family"] or found["second"]["family"], **union}
    result = {}
    if case.get("reference_family"):
        accepted = case["reference_family"]
        accepted = {_family(name) for name in (accepted if isinstance(accepted, list) else [accepted])}
        result["family"] = {name: {"predicted": f["family"], "correct": f["family"] in accepted}
                            for name, f in found.items() if name != "merged"}
    for label, key in (("expected_impacts", "impacts"), ("expected_techniques", "techniques"),
                       ("expected_block", "blocked")):
        if isinstance(case.get(label), list):
            expected = {str(v).upper() if key == "techniques" else str(v).lower() if key == "blocked" else str(v)
                        for v in case[label]}
            result[key] = {name: score_sets(expected, f[key]) for name, f in found.items()}
    if second is not None:
        try:
            compared = compare_payloads(payload, second)
            result["agreement"] = {d["id"]: {"title": d["title"], "jaccard": d["jaccard"], "counts": d["counts"]}
                                   for d in compared["dimensions"]}
            result["relation"] = compared["relation"]
        except ValueError as exc:
            result["agreement_error"] = str(exc)
    return result


def aggregate(rows: list[dict]) -> dict:
    """Micro-averaged totals over the cases that carry each label."""
    scored = [row.get("labels") or {} for row in rows]
    summary = {"cases": len(rows)}
    family = {}
    for name in ("primary", "second"):
        marks = [labels["family"][name]["correct"] for labels in scored if name in labels.get("family", {})]
        if marks:
            family[name] = {"correct": sum(marks), "total": len(marks), "accuracy": round(sum(marks) / len(marks), 3),
                            "ci95": wilson(sum(marks), len(marks))}
    summary["family"] = family
    for key in ("impacts", "techniques", "blocked"):
        summary[key] = {}
        for name in SOURCES:
            parts = [labels[key][name] for labels in scored if name in labels.get(key, {})]
            if parts:
                summary[key][name] = {**rates(*(sum(p[c] for p in parts) for c in ("tp", "fp", "fn"))),
                                      "cases": len(parts)}
    extraction = [row["extraction"] for row in rows if row.get("extraction")]
    summary["extraction"] = {"primary": {**rates(*(sum(e[c] for e in extraction) for c in ("tp", "fp", "fn"))),
                                         "cases": len(extraction)}} if extraction else {}
    agreement = {}
    for labels in scored:
        for dim, value in (labels.get("agreement") or {}).items():
            if value["jaccard"] is not None:
                agreement.setdefault(dim, {"title": value["title"], "values": []})["values"].append(value["jaccard"])
    summary["agreement"] = {dim: {"title": v["title"], "cases": len(v["values"]),
                                  "mean_jaccard": round(sum(v["values"]) / len(v["values"]), 3)}
                            for dim, v in agreement.items()}
    return summary


def _cell(score: dict | None) -> str:
    if not score:
        return "—"

    def pct(value, interval):
        return "—" if value is None else f"{value:.0%} [{interval[0]:.0%}–{interval[1]:.0%}]"
    return (f"P {pct(score['precision'], score['precision_ci95'])}; R {pct(score['recall'], score['recall_ci95'])}; "
            f"F1 {'—' if score['f1'] is None else format(score['f1'], '.2f')} (n={score['cases']})")


def results_markdown(summary: dict) -> str:
    """One table for the report: rows are what the program does, columns are the sources."""
    lines = ["| Chỉ số | Nguồn chính | Nguồn thứ hai | Gộp hai nguồn |", "|---|---|---|---|"]
    titles = {"extraction": "Trích IOC", "impacts": "Nhóm tác động", "techniques": "Kỹ thuật ATT&CK",
              "blocked": "Đích được đề xuất chặn"}
    for key, title in titles.items():
        block = summary.get(key) or {}
        if block:
            lines.append(f"| {title} | " + " | ".join(_cell(block.get(name)) for name in SOURCES) + " |")
    family = summary.get("family") or {}
    if family:
        def acc(item):
            return "—" if not item else (f"{item['correct']}/{item['total']} = {item['accuracy']:.0%} "
                                         f"[{item['ci95'][0]:.0%}–{item['ci95'][1]:.0%}]")
        lines.append(f"| Họ mã độc đúng | {acc(family.get('primary'))} | {acc(family.get('second'))} | — |")
    lines += ["", "P: precision, R: recall, trong ngoặc vuông là khoảng tin cậy 95% (Wilson), n là số ca có nhãn.",
              "Với đích được đề xuất chặn: sai dương là chặn nhầm, sai âm là bỏ sót."]
    if summary.get("agreement"):
        lines += ["", "| Chiều đối chiếu | Jaccard trung bình | Số ca |", "|---|---|---|"]
        lines += [f"| {v['title']} | {v['mean_jaccard']:.2f} | {v['cases']} |" for v in summary["agreement"].values()]
        lines += ["", "Mức đồng thuận giữa hai sandbox không phải độ chính xác."]
    return "\n".join(lines) + "\n"
