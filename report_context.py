"""Read report metadata only. Never render SVG or execute commands from a report."""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from xml.etree import ElementTree

# DLLs that support an analysis hint (.NET runtime, credential stores, file unlocking, account queries, HTTP, dumps).
NOTABLE_MODULES = {"mscoree.dll", "clr.dll", "coreclr.dll", "vaultcli.dll", "dpapi.dll", "rstrtmgr.dll", "samlib.dll",
                   "wininet.dll", "winhttp.dll", "dbghelp.dll"}
UUID = r"[0-9a-fA-F]{8}(?:[-_][0-9a-fA-F]{4}){3}[-_][0-9a-fA-F]{12}"
EDGE = re.compile(rf"^NODE_({UUID})(?::[a-z]+)?->NODE_({UUID})(?::[a-z]+)?$")


def graph_context(processes: dict, rows: list[dict]) -> dict:
    """Accept unambiguous, solid UUID edges; retain graph evidence as text, not SVG DOM."""
    raw = processes.get("graphSvg") or ""
    result = {"status": "not_available", "relations": [], "warnings": []}
    if not isinstance(raw, str) or not raw:
        return result
    if len(raw) > 8_000_000 or re.search(r"<!\s*(?:DOCTYPE|ENTITY)", raw, re.I):
        return {**result, "status": "rejected", "warnings": ["SVG quá lớn hoặc chứa khai báo XML không cho phép."]}
    try:
        root = ElementTree.fromstring(raw)
    except ElementTree.ParseError:
        return {**result, "status": "invalid", "warnings": ["Không đọc được sơ đồ tiến trình."]}
    counts = Counter(r["uuid"] for r in rows if r.get("uuid"))
    unique = {r["uuid"]: r for r in rows if r.get("uuid") and counts[r["uuid"]] == 1}
    nodes, candidates, rejected_nodes = {}, defaultdict(list), set()
    for group in root.iter():
        if group.get("class") not in {"node", "edge"}:
            continue
        title = next((c.text or "" for c in group if c.tag.rsplit("}", 1)[-1] == "title"), "").strip()
        if group.get("class") == "node":
            match = re.fullmatch(rf"NODE_({UUID})", title)
            if match:
                uid = match[1].replace("_", "-").lower()
                # The node id carries UUID|PID|epoch_ms. Only accept matching UUID/PID.
                identity = re.fullmatch(rf"({UUID})(?:-[^|]*)?\|(\d+)\|(\d{{13}})", group.get("id", ""))
                if identity and uid in unique and (identity[1].lower() != uid or int(identity[2]) != unique[uid]["pid"]):
                    rejected_nodes.add(uid)
                if identity and uid in unique and identity[1].lower() == uid and int(identity[2]) == unique[uid]["pid"]:
                    nodes[uid] = int(identity[3])
        else:
            match = EDGE.fullmatch(title)
            dashed = any(c.get("stroke-dasharray") for c in group.iter())
            labels = [c.text for c in group.iter() if c.tag.rsplit("}", 1)[-1] == "text" and c.text]
            if not match or dashed or labels:
                continue  # MAIN/start and annotated/injection edges are not parent assertions.
            parent, child = (v.replace("_", "-").lower() for v in match.groups())
            if parent in unique and child in unique and parent != child:
                candidates[child].append((parent, title))
    parent_map = {}
    for child, edges in candidates.items():
        if child in rejected_nodes or any(parent in rejected_nodes for parent, _ in edges):
            result["warnings"].append("Bỏ quan hệ có UUID/PID mâu thuẫn: " + child)
            continue
        parents = {p for p, _ in edges}
        if len(parents) == 1:
            parent_map[child] = edges[0]
        else:
            result["warnings"].append("Bỏ quan hệ có nhiều UUID cha: " + child)
    cyclic = set()
    for start in parent_map:
        seen, current = set(), start
        while current in parent_map:
            if current in seen:
                cyclic.update(seen)
                break
            seen.add(current)
            current = parent_map[current][0]
    for uid, row in unique.items():
        if uid in nodes:
            row["startTime"] = nodes[uid]
            row["timeBasis"] = "graph_node_epoch_ms"
        if uid not in parent_map or uid in cyclic:
            continue
        parent, title = parent_map[uid]
        row.update(parentUuid=parent, ppid=unique[parent]["pid"], ppidBasis="graph_uuid")
        result["relations"].append({"parentUuid": parent, "childUuid": uid, "parentPid": unique[parent]["pid"],
                                    "pid": row["pid"], "edge": title, "basis": "graph_uuid"})
    if cyclic:
        result["warnings"].append("Bỏ quan hệ tạo vòng lặp trong sơ đồ.")
    result["status"] = "parsed"
    return result


def static_context(data: dict) -> dict:
    src = data.get("staticInformation") or {}
    rows = []
    for group in src.get("exif", []) or []:
        if not isinstance(group, list) or len(group) < 2 or not isinstance(group[1], list):
            continue
        for cell in group[1][:300]:
            if isinstance(cell, list) and len(cell) >= 2 and isinstance(cell[1], (str, int, float)):
                rows.append({"group": str(group[0])[:100], "name": str(cell[0])[:120], "value": str(cell[1])[:2000]})
    trid = [{"extension": str(r.get("extension", ""))[:30], "value": str(r.get("value", ""))[:400]}
            for r in (src.get("trid") or [])[:50] if isinstance(r, dict)]
    signature = src.get("signature") or src.get("digitalSignature")
    signature_status = "not_reported"
    if isinstance(signature, dict):
        status = str(signature.get("status", "")).lower()
        if status in {"valid", "invalid", "trusted", "untrusted", "unsigned", "signed"}:
            signature_status = "reported_" + status
            rows.append({"group": "Signature", "name": "SignatureStatus", "value": status})
    return {"metadata": rows[:600], "trid": trid,
            "analysisTime": str((data.get("general") or {}).get("rawAnalysisDate") or ""),
            "signature_status": signature_status}
