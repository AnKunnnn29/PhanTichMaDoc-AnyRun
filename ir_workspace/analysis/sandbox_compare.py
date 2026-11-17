"""Cross-check two sandbox analyses of the same sample, dimension by dimension.

Two sandboxes agreeing does not make a finding true, and disagreeing does not make it
false: a dead C2, VM detection or a different run time all change what is observed.
So nothing is dropped here. Each item is reported as seen by both sources or by one,
and an item seen by one source is "not confirmed by the other", not an error.
"""
from __future__ import annotations

import re

NOT_SUSPICIOUS_ROLES = {"benign_infrastructure", "local_network", "dns_only"}
C2_ROLES = {"config_c2", "known_c2"}
MAX_ITEMS = 60


def source_label(payload: dict) -> str:
    source = str(payload.get("source", "")).lower()
    return "Triage" if source.startswith("triage") else "Any.Run"


def _hashes(payload: dict) -> set[str]:
    rows = (payload.get("evidence_bundle") or {}).get("evidence", [])
    found = {str(row.get("value", "")).lower() for row in rows if row.get("type") == "sha256"}
    return {h for h in found | {_main_hash(payload)} if re.fullmatch(r"[0-9a-f]{64}", h)}


def _main_hash(payload: dict) -> str:
    return str((payload.get("file") or {}).get("sha256") or "").lower()


def relation(a: dict, b: dict) -> str:
    """How the two analysed objects relate: the same file, or one sample inside the other's run."""
    main_a, main_b = _main_hash(a), _main_hash(b)
    if main_a and main_a == main_b:
        return "same_file"
    if (main_a and main_a in _hashes(b)) or (main_b and main_b in _hashes(a)):
        return "sample_in_other_run"
    return ""


def _family(payload: dict) -> set[str]:
    name = re.sub(r"[^a-z0-9]+", "", str((payload.get("threat") or {}).get("threat_name") or "").lower())
    return {name} if name else set()


def _destinations(payload: dict, roles=None) -> set[str]:
    profiles = (payload.get("network_profiles") or {}).values()
    return {str(p.get("value", "")).lower() for p in profiles if p.get("value") and
            (p.get("role") in roles if roles else p.get("role") not in NOT_SUSPICIOUS_ROLES)}


def _dropped(payload: dict) -> set[str]:
    rows = (payload.get("evidence_bundle") or {}).get("evidence", [])
    return {str(row.get("value", "")).lower() for row in rows
            if row.get("type") == "sha256" and "/dropped/" in str(row.get("source_path", ""))}


def _techniques(payload: dict) -> set[str]:
    return {str(row.get("technique_id", "")).upper() for row in payload.get("mitre_mappings") or []
            if row.get("technique_id")}


def _impacts(payload: dict) -> set[str]:
    return {c["id"] for c in (payload.get("impact_analysis") or {}).get("categories", []) if c.get("id")}


DIMENSIONS = [
    ("family", "Họ mã độc", _family),
    ("suspicious_destinations", "Đích mạng đáng ngờ", _destinations),
    ("c2", "C2 (cấu hình hoặc nguồn tình báo)", lambda p: _destinations(p, C2_ROLES)),
    ("dropped_files", "Tệp thả ra (SHA256)", _dropped),
    ("attack_techniques", "Kỹ thuật ATT&CK", _techniques),
    ("impact_categories", "Nhóm tác động", _impacts),
]


def compare_payloads(a: dict, b: dict) -> dict:
    """Compare two pipeline payloads. Raises ValueError when they are not about the same sample."""
    related = relation(a, b)
    if not related:
        raise ValueError("Hai báo cáo không cùng một mẫu: SHA256 của mẫu này không xuất hiện trong báo cáo kia")
    titles = {c["id"]: c.get("title", c["id"]) for p in (a, b)
              for c in (p.get("impact_analysis") or {}).get("categories", []) if c.get("id")}
    dimensions = []
    for dim_id, title, extract in DIMENSIONS:
        set_a, set_b = extract(a), extract(b)
        union = set_a | set_b

        def show(items):
            return [titles.get(item, item) for item in sorted(items)][:MAX_ITEMS]

        dimensions.append({
            "id": dim_id, "title": title,
            "both": show(set_a & set_b), "only_a": show(set_a - set_b), "only_b": show(set_b - set_a),
            "counts": {"both": len(set_a & set_b), "only_a": len(set_a - set_b), "only_b": len(set_b - set_a)},
            # No observation on either side says nothing about agreement.
            "jaccard": round(len(set_a & set_b) / len(union), 3) if union else None,
        })
    scored = [d["jaccard"] for d in dimensions if d["jaccard"] is not None]
    return {
        "labels": {"a": source_label(a), "b": source_label(b)},
        "cases": {"a": a.get("case_id"), "b": b.get("case_id")},
        "samples": {"a": _main_hash(a), "b": _main_hash(b)}, "relation": related,
        "dimensions": dimensions,
        "mean_jaccard": round(sum(scored) / len(scored), 3) if scored else None,
        "note": ("Mức đồng thuận không phải độ chính xác. Mục chỉ một nguồn thấy là chưa được nguồn kia xác nhận, "
                 "không phải sai: hai sandbox chạy mẫu ở thời điểm, môi trường và thời lượng khác nhau."),
    }


def comparison_lines(payload: dict) -> list[str]:
    """Plain text for the exporters; callers escape their own format."""
    comparison = payload.get("sandbox_comparison")
    if not comparison:
        return []
    a, b = comparison["labels"]["a"], comparison["labels"]["b"]
    related = "cùng một tệp" if comparison["relation"] == "same_file" else "mẫu này nằm trong lần chạy kia"
    lines = [f"Đối chiếu đa nguồn: {a} và {b}",
             f"Mẫu {a}: {comparison['samples']['a']} | Mẫu {b}: {comparison['samples']['b']} | "
             f"Quan hệ: {related}",
             comparison["note"]]
    for d in comparison["dimensions"]:
        score = "không có quan sát" if d["jaccard"] is None else f"Jaccard {d['jaccard']}"
        c = d["counts"]
        lines.append(f"{d['title']}: cả hai {c['both']}, chỉ {a} {c['only_a']}, chỉ {b} {c['only_b']} ({score})")
        for label, key in (("Cả hai", "both"), (f"Chỉ {a}", "only_a"), (f"Chỉ {b}", "only_b")):
            if d[key]:
                lines.append(f"  {label}: " + ", ".join(d[key][:12]) + (" ..." if len(d[key]) > 12 else ""))
    if comparison.get("mean_jaccard") is not None:
        lines.append(f"Đồng thuận trung bình trên các chiều có quan sát: {comparison['mean_jaccard']}")
    return lines
