"""Versioned catalogue checks plus conservative, evidence-linked mapping hypotheses."""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path, PureWindowsPath


@lru_cache(maxsize=1)
def catalogue():
    return json.loads((Path(__file__).parent / "data" / "attack_catalog.json").read_text(encoding="utf-8"))


def map_evidence(bundle):
    catalog = catalogue()
    mappings = {}

    def add(tid, row, origin, reason):
        tech = catalog["techniques"].get(tid)
        active = bool(tech and not tech["revoked"] and not tech["deprecated"])
        key = (tid, origin)
        if key not in mappings:
            mappings[key] = {"technique_id": tid, "name": tech["name"] if tech else "Unknown technique ID",
                "tactics": tech["tactics"] if tech else [], "evidence_ids": [], "origin": origin, "reason": reason,
                "catalog_version": catalog["version"], "catalog_validation": "active" if active else "unknown_or_retired",
                "assessment_status": "hypothesis" if origin != "source_report" else "reported_not_independently_verified",
                "url": tech["url"] if tech else ""}
        mappings[key]["evidence_ids"].append(row["id"])

    for row in bundle["evidence"]:
        ctx = row["context"]
        if row["type"] == "mitre":
            origin = ctx.get("origin", "source_report")
            add(row["value"].upper(), row, origin, "Technique được báo cáo/adapter đề xuất; cần đối chiếu hành vi nguồn.")
        elif row["type"] == "process":
            if ctx.get("isInjected") is True:
                add("T1055", row, "rule_hypothesis", "Nguồn gắn cờ isInjected; analyst xác minh cơ chế injection.")
            name = PureWindowsPath(row["value"]).name.lower()
            if name in {"powershell.exe", "pwsh.exe"}:
                add("T1059.001", row, "rule_hypothesis", "Nguồn liệt kê PowerShell process; chưa xác nhận nội dung lệnh độc hại.")
        elif row["type"] == "registry":
            operation = str(ctx.get("operation") or ctx.get("action") or "").lower()
            if operation in {"write", "setvalue", "regsetvalue", "create"} and "\\currentversion\\run" in row["value"].lower():
                add("T1547.001", row, "rule_hypothesis", "Có thao tác ghi Run key được nguồn báo cáo; cần kiểm tra giá trị và file đích.")
    return list(mappings.values()), {"version": catalog["version"], "source_url": catalog["source_url"],
                                     "source_sha256": catalog["source_sha256"]}
