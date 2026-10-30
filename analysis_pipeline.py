"""Shared evidence -> bounded Agent -> reviewed playbook pipeline for CLI and web."""
from __future__ import annotations

import copy
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from analyzer import MalwareAnalyzer
from analysis_agent import agent_settings, investigate
from case_agent import CASE_PROMPT_VERSION, apply_case_plan, investigate_case
from evidence import PIPELINE_VERSION, collect_evidence, digest, validate_bundle
from incident_response import IncidentResponseGenerator
from validation import validate_report
from mitre_mapping import map_evidence, catalogue
from response_policy import exclusions
from operational_guidance import apply_guidance
from network_intel import build_network_profiles, enrich_network_profiles
from impact_analysis import analyze_impact
from remediation import build_case_actions, merge_actions


def analysis_key(report, iocs) -> str:
    # Entire inputs AND analysis settings: never family names or shared dropped-file hashes.
    return "case-" + digest([PIPELINE_VERSION, CASE_PROMPT_VERSION, agent_settings(), catalogue()["source_sha256"], report, iocs])


def build_behavior(bundle):
    evidence = bundle["evidence"]
    events, edges = [], []
    processes = {}
    for row in evidence:
        if row["type"] == "process":
            pid = row["context"].get("pid")
            if pid:
                processes[str(pid)] = row["id"]
    for row in evidence:
        if row["type"] == "mitre":
            continue
        context = row["context"]
        timestamp = context.get("timestamp") or context.get("time")
        events.append({"step": len(events) + 1, "stage": row["type"], "event": row["value"],
                       "timestamp": timestamp, "order_basis": "source_timestamp" if timestamp else "source_order_not_chronology",
                       "evidence": row["id"], "evidence_ids": [row["id"]], "mitre": "",
                       "ir_action": "Xác minh artifact trên endpoint/log; chưa suy ra quan hệ nhân quả."})
        pid, ppid = context.get("pid"), context.get("ppid")
        if row["type"] == "process" and ppid and str(ppid) in processes:
            # Public reports name the parent without its PID; a unique-name match is an inference.
            inferred = context.get("ppidBasis") == "unique_parent_name"
            edges.append({"source": processes[str(ppid)], "target": row["id"],
                          "relation": "parent_by_unique_name" if inferred else "reported_parent_process",
                          "evidence_ids": [processes[str(ppid)], row["id"]],
                          "assessment_status": "inferred" if inferred else "reported"})
        elif row["type"] != "process" and pid and str(pid) in processes:
            edges.append({"source": processes[str(pid)], "target": row["id"], "relation": "reported_process_artifact",
                          "evidence_ids": [processes[str(pid)], row["id"]], "assessment_status": "reported"})
    return {"events": events, "relations": edges,
            "limitations": ["Thứ tự nguồn không chứng minh trình tự thời gian hoặc quan hệ nhân quả.",
                            "Không dựng quan hệ process/artifact khi nguồn thiếu PID.",
                            "Quan hệ cha-con có nhãn inferred được suy ra từ tên tiến trình cha duy nhất, không phải PPID của nguồn."]}


def run_pipeline(report, iocs, source="manual"):
    started = time.perf_counter()
    validate_report(report, iocs)
    report, iocs = copy.deepcopy(report), copy.deepcopy(iocs)
    result = MalwareAnalyzer().parse_report(report, iocs)
    bundle = collect_evidence(report, iocs)
    validate_bundle(bundle)
    # Keep malformed candidates in the evidence viewer, but exclude them from
    # operational blocklists and command/query templates.
    valid = [o for o in bundle["observables"] if o["valid"]]
    result.iocs.ips = [o["value"] for o in valid if o["type"] == "ip"]
    result.iocs.domains = [o["value"] for o in valid if o["type"] == "domain"]
    result.iocs.urls = [o["value"] for o in valid if o["type"] == "url"]
    result.iocs.file_hashes = [{o["type"]: o["value"]} for o in valid if o["type"] in {"md5", "sha1", "sha256"}]
    result.iocs.filenames = [o["value"] for o in valid if o["type"] == "file"]
    network_profiles = build_network_profiles(bundle)
    # Simulated demo indicators are not worth (or safe to imply as) real intel lookups.
    threat_intel = enrich_network_profiles(network_profiles, enabled=not str(source).startswith("demo"))
    # The per-IOC agent does not feed the playbook or the case agent, so it runs alongside them.
    ioc_pool = ThreadPoolExecutor(max_workers=1)
    ioc_future = ioc_pool.submit(investigate, bundle, network_profiles)
    impact = analyze_impact(report, bundle, network_profiles)
    behavior = build_behavior(bundle)
    mappings, catalog_meta = map_evidence(bundle)
    result.threat_info.mitre_techniques = [{"id": m["technique_id"], "name": m["name"],
        "tactic": ", ".join(t.replace("-", " ").title() for t in m["tactics"])}
        for m in {m["technique_id"]: m for m in mappings if m["catalog_validation"] == "active"}.values()]
    playbook = IncidentResponseGenerator().generate(result)
    excluded = exclusions(bundle)
    listed = {row["value"] for row in excluded}
    # Whitelisted OS/CDN traffic and sandbox-local addresses are context, not blocking targets.
    # Unrated destinations are watched in logs, not blocked, until there is evidence of their role.
    excluded += [{"type": p["type"], "value": p["value"],
                  "reason": p["meaning"] + (" Theo dõi trong log; chưa đủ bằng chứng để chặn." if p["response"] == "monitor"
                                            else " Không đưa vào danh sách chặn."),
                  "evidence_ids": p["evidence_ids"], "source_url": ""}
                 for p in network_profiles.values()
                 if p["response"] in {"do_not_block", "ignore", "monitor"} and p["value"] not in listed]
    for field, kind in (("ip_addresses", "ip"), ("domains", "domain"), ("urls", "url")):
        denied = {o["value"] for o in excluded if o["type"] == kind}
        playbook.ioc_blocklist[field] = [v for v in playbook.ioc_blocklist.get(field, []) if v not in denied]
    playbook.timeline = behavior["events"]
    # Do not imply independent ATT&CK validation or a timestamp that does not exist.
    by_type = {}
    for row in bundle["evidence"]:
        by_type.setdefault(row["type"], []).append(row["id"])
    for n, action in enumerate(playbook.actions):
        action.id = "action-" + digest([analysis_key(report, iocs), n, action.title])[:20]
        category = (action.category + " " + action.title).lower()
        kinds = {"file", "md5", "sha1", "sha256"}
        if any(term in category for term in ("mạng", "network", "c2", "scope")):
            kinds = {"ip", "domain", "url"}
        elif "process" in category or "tiến trình" in category or "bộ nhớ" in category:
            kinds = {"process", "mitre"}
        elif "persistence" in category or "registry" in category:
            kinds = {"registry", "mitre"}
        action.evidence_ids = [eid for kind in sorted(kinds) for eid in by_type.get(kind, [])]
        # These are candidate supporting references; reviewers must assess semantic relevance.
        action.preconditions = ["Xác minh evidence và mục tiêu trên hệ thống thực tế.",
                                "Bảo toàn bằng chứng; chuyên viên xem xét tác động trước khi áp dụng."]
        action.risks = ["Có thể gián đoạn dịch vụ hoặc làm mất bằng chứng nếu áp dụng sai mục tiêu."]
        action.blocked = not bool(action.evidence_ids)
        apply_guidance(action, result, bundle)
        action.description = "Khuyến nghị có điều kiện, cần analyst đối chiếu evidence trước khi áp dụng. " + action.description
        action.nist_function = "DE" if "identification" in action.phase.lower() else "RC" if "recovery" in action.phase.lower() else "ID.IM" if "lessons" in action.phase.lower() else "RS"
    threat = {"verdict": result.threat_info.verdict, "threat_name": result.threat_info.threat_name,
              "threat_level": result.threat_info.threat_level, "tags": result.threat_info.tags}
    # Actions built from this case's facts replace the generic template of the same kind.
    evidence_by_id = {e["id"]: e for e in bundle["evidence"]}
    case_actions = build_case_actions(report, impact, network_profiles, threat)
    for n, action in enumerate(case_actions):
        action.id = "action-" + digest([analysis_key(report, iocs), "case", n, action.title])[:20]
        action.blocked = not bool(action.evidence_ids)
        action.related_observations = [{"id": i, "type": evidence_by_id[i]["type"], "value": evidence_by_id[i]["value"]}
                                       for i in action.evidence_ids if i in evidence_by_id][:6]
        action.nist_function = "DE" if "identification" in action.phase.lower() else "RC" if "recovery" in action.phase.lower() else "ID.IM" if "lessons" in action.phase.lower() else "RS"
    playbook.actions = merge_actions(playbook.actions, case_actions)
    case_agent = investigate_case(bundle, behavior, mappings, [
        {"id": a.id, "title": a.title, "phase": a.phase, "category": a.category, "priority": a.priority,
         "response_profile": a.response_profile, "objective": a.objective, "evidence_ids": a.evidence_ids, "origin": a.origin}
        for a in playbook.actions], threat, network_profiles, impact)
    apply_case_plan(playbook.actions, case_agent)
    try:
        agent = ioc_future.result()
    finally:
        ioc_pool.shutdown(wait=True)
    result.research = {
        "case_id": "case-" + uuid.uuid4().hex, "analysis_fingerprint": analysis_key(report, iocs),
        "pipeline_version": PIPELINE_VERSION, "source": source,
        "evidence_bundle": bundle, "agent_analysis": agent, "case_agent": case_agent, "behavior_chain": behavior,
        "network_profiles": network_profiles, "threat_intel_status": threat_intel, "impact_analysis": impact, "mitre_mappings": mappings,
        "mitre_catalog": catalog_meta,
        "response_exclusions": excluded,
        "analysis_status": "insufficient_data" if result.threat_info.verdict == "Unknown" else "completed_with_review_required",
        "nist": {"revision": "SP 800-61 Rev.3", "framework": "CSF 2.0", "mapping": "local operational mapping; not a compliance certification"},
        "review_revision": 0, "review_history": [],
        "metrics": {"pipeline_ms": round((time.perf_counter() - started) * 1000, 2),
                    "ioc_count": len(agent["findings"]), "evidence_count": len(bundle["evidence"]),
                    "source_reference_integrity": True, "semantic_accuracy": "not_measured"},
    }
    return result, playbook


def research_markdown(payload: dict) -> str:
    """One renderer shared by CLI/web Markdown exports; escape report-controlled markup."""
    import html
    def safe(value):
        return html.escape(str(value), quote=True).replace("|", "&#124;").replace("`", "&#96;").replace("\n", " ")
    agent = payload.get("agent_analysis")
    if not agent:
        return ""
    lines = ["", "## Phân tích IOC và bằng chứng", "",
             f"Case: {safe(payload.get('case_id'))}",
             f"Agent: {safe(agent['mode'])}; model: {safe(agent['model'])}; prompt: {safe(agent['prompt_version'])}",
             "Kiểm tra tham chiếu không thay thế đánh giá tính đúng đắn của nhận định bởi analyst.", "",
             "| IOC ID | Vai trò dự kiến | Nguy cơ giả định | Diễn giải | Ảnh hưởng | Cần xác minh | Evidence |", "|---|---|---|---|---|---|---|"]
    for row in agent["findings"]:
        lines.append("| " + " | ".join(safe(row[k]) for k in ("ioc_id", "role", "severity", "explanation", "potential_impact", "verification_needed", "evidence_ids")) + " |")
    impact = payload.get("impact_analysis")
    if impact and impact["categories"]:
        lines += ["", "### Tác động và thiệt hại", "", safe(impact["summary"]), ""]
        for c in impact["categories"]:
            lines += [f"#### {safe(c['title'])} ({safe(c['severity'])})"] + ["- " + safe(f) for f in c["facts"]]
            lines += ["", "Ảnh hưởng: " + safe(c["impact"]), "Hướng xử lý: " + safe(c["response_hint"]),
                      "Evidence: " + safe(", ".join(c["evidence_ids"][:10])), ""]
        lines += ["- " + safe(x) for x in impact["limitations"]]
    profiles = [p for p in (payload.get("network_profiles") or {}).values()
                if p["role"] not in {"benign_infrastructure", "local_network"}]
    if payload.get("network_profiles"):
        lines += ["", "### Phân tích đích mạng", "",
                  f"{len(payload['network_profiles']) - len(profiles)} đích là hạ tầng hợp lệ/mạng nội bộ sandbox, không đưa vào danh sách chặn.",
                  "", "| Đích | Vai trò | Mức | Diễn giải | Ảnh hưởng | Cần xác minh |", "|---|---|---|---|---|---|"]
        for p in profiles:
            lines.append("| " + " | ".join(safe(p[k]) for k in ("value", "role", "severity", "summary", "impact", "verify")) + " |")
    case = payload.get("case_agent")
    if case:
        a = case["assessment"]
        lines += ["", "### Agent điều tra hồ sơ", "",
                  f"Chế độ: {safe(case['mode'])}; model: {safe(case['model'])}; prompt: {safe(case['prompt_version'])}; "
                  f"số bước: {case['steps_used']}/{case['max_steps']}; evidence đã đọc: {len(case['evidence_read'])}",
                  "", safe(a["summary"]), "", f"Ảnh hưởng: {safe(a['impact']['severity'])} — {safe(a['impact']['summary'])}",
                  "", "| Giai đoạn | MITRE | Trạng thái | Nhận định | Evidence |", "|---|---|---|---|---|"]
        for s in a["behavior_chain"]:
            lines.append("| " + " | ".join(safe(v) for v in (s["stage"], ", ".join(s["mitre"]), s["assessment_status"], s["summary"], ", ".join(s["evidence_ids"]))) + " |")
        lines += ["", "| Action ID | Quyết định Agent | Ưu tiên | Lý do |", "|---|---|---|---|"]
        for row in a["action_plan"]:
            lines.append("| " + " | ".join(safe(v) for v in (row["action_id"], row["decision"], row["priority"], row["rationale"])) + " |")
        lines += [""] + ["- Cần xác minh: " + safe(q) for q in a["open_questions"]]
        lines += [""] + ["- Bước " + safe(t["step"]) + ": " + safe(t["tool"]) + " → " + safe(t["status"]) for t in case["tool_trace"]]
        lines += ["- Cảnh báo: " + safe(w) for w in case["warnings"]]
    lines += ["", "### Bằng chứng nguồn", "", "| ID | Loại | Giá trị | Nguồn và vị trí | SHA256 nguồn |", "|---|---|---|---|---|"]
    for row in payload["evidence_bundle"]["evidence"]:
        lines.append("| " + " | ".join(safe(v) for v in (row["id"], row["type"], row["value"], row["source_id"] + row["source_path"], row["source_sha256"])) + " |")
    if payload.get("response_exclusions"):
        lines += ["", "### Ngoại lệ ứng cứu", "", "| Đích | Lý do | Nguồn |", "|---|---|---|"]
        for row in payload["response_exclusions"]:
            lines.append("| " + " | ".join(safe(row[k]) for k in ("value", "reason", "source_url")) + " |")
    lines += ["", "### Xem xét khuyến nghị", "", "| Action ID | Trạng thái | Người xem xét | Lý do |", "|---|---|---|---|"]
    for row in payload["playbook"]["actions"]:
        review = row.get("review", {})
        lines.append("| " + " | ".join(safe(v) for v in (row.get("id"), row.get("status"), review.get("reviewer", ""), review.get("reason", ""))) + " |")
    lines += ["", "### Hướng dẫn khắc phục theo từng đề xuất", ""]
    for row in payload['playbook']['actions']:
        lines += ['#### ' + safe(row.get('title', '')), safe(row.get('objective', '')), safe(row.get('target_scope', ''))]
        lines += [f'{index}. {safe(step)}' for index, step in enumerate(row.get('steps', []), 1)]
        lines += ['Tiêu chí xác minh: ' + safe(' '.join(row.get('verification', []))), 'Nếu phát sinh ảnh hưởng: ' + safe(row.get('rollback', '')), '']
    return "\n".join(lines) + "\n"
