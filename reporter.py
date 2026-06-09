"""
reporter.py
~~~~~~~~~~~
In kết quả ra terminal (rich) và xuất file báo cáo (Markdown + PDF).
"""

from __future__ import annotations
import os
import json
import datetime
import html
import textwrap
from pathlib import Path
from typing import Optional, Any

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.columns import Columns
from rich.rule import Rule
from rich.markup import escape

from analyzer import MalwareAnalysisResult
from incident_response import IncidentResponsePlaybook, IncidentAction

console = Console()

# ─────────────────────────────────────────────────────────────────────────────
# Severity color mapping
# ─────────────────────────────────────────────────────────────────────────────
_SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH": "bold orange1",
    "MEDIUM": "bold yellow",
    "LOW": "bold green",
    "UNKNOWN": "dim",
}

_PRIORITY_LABEL = {
    1: ("[P1-CRITICAL]", "red"),
    2: ("[P2-HIGH]", "orange1"),
    3: ("[P3-MEDIUM]", "yellow"),
    4: ("[P4-LOW]", "green"),
}


# ─────────────────────────────────────────────────────────────────────────────
# Terminal reporter
# ─────────────────────────────────────────────────────────────────────────────


class TerminalReporter:
    """In kết quả đẹp ra terminal bằng Rich."""

    def print_analysis(self, result: MalwareAnalysisResult) -> None:
        threat = result.threat_info
        style = _SEVERITY_STYLE.get(
            "CRITICAL" if threat.threat_level >= 2 else ("MEDIUM" if threat.threat_level == 1 else "LOW"), "white"
        )

        console.print()
        console.print(Rule("[bold cyan]╔ KẾT QUẢ PHÂN TÍCH ANY.RUN ╗[/bold cyan]", style="cyan"))

        # File info panel
        if result.file_info:
            f = result.file_info
            console.print(
                Panel(
                    f"[bold]Tên file:[/bold] {escape(f.name)}\n"
                    f"[bold]Loại:[/bold] {f.file_type} | [bold]MIME:[/bold] {f.mime_type}\n"
                    f"[bold]Kích thước:[/bold] {f.size:,} bytes\n"
                    f"[bold]MD5:[/bold]    [dim]{f.md5}[/dim]\n"
                    f"[bold]SHA1:[/bold]   [dim]{f.sha1}[/dim]\n"
                    f"[bold]SHA256:[/bold] [dim]{f.sha256}[/dim]",
                    title="[bold blue]📄 Thông tin mẫu mã độc[/bold blue]",
                    border_style="blue",
                )
            )

        # Threat verdict
        verdict_text = Text()
        verdict_text.append("● Kết luận: ", style="bold")
        verdict_text.append(threat.verdict, style=style + " bold")
        verdict_text.append(f"  (Threat Level {threat.threat_level}/4)", style="dim")
        console.print(
            Panel(
                f"{verdict_text}\n"
                f"[bold]Tên mã độc:[/bold] {escape(threat.threat_name or 'Chưa xác định')}\n"
                f"[bold]Tags:[/bold] {', '.join(threat.tags) or 'N/A'}\n"
                f"[bold]Môi trường:[/bold] {result.os_env}\n"
                f"[bold]Any.Run URL:[/bold] [link={result.analysis_url}]{result.analysis_url}[/link]",
                title="[bold red]⚠️  Mức độ đe dọa[/bold red]",
                border_style="red" if threat.threat_level >= 2 else "yellow",
            )
        )

        # MITRE table
        if threat.mitre_techniques:
            table = Table(
                title="🎯 MITRE ATT&CK Techniques", box=box.ROUNDED, border_style="magenta", header_style="bold magenta"
            )
            table.add_column("ID", style="cyan", no_wrap=True)
            table.add_column("Tên kỹ thuật", style="white")
            table.add_column("Tactic", style="yellow")
            for t in threat.mitre_techniques[:15]:
                table.add_row(t.get("id", ""), t.get("name", ""), t.get("tactic", ""))
            console.print(table)

        # Network IOC table
        net = result.network
        if net.ip_addresses or net.domains:
            net_table = Table(
                title="🌐 Hoạt động mạng (C2)", box=box.SIMPLE_HEAD, border_style="red", header_style="bold red"
            )
            net_table.add_column("Loại", style="bold")
            net_table.add_column("Giá trị", style="red")
            for ip in net.ip_addresses[:10]:
                net_table.add_row("IP Address", ip)
            for d in net.domains[:10]:
                net_table.add_row("Domain", d)
            for u in net.urls[:5]:
                net_table.add_row("URL", escape(u[:80]))
            console.print(net_table)

        # Process info
        procs = result.processes
        if procs.injected_processes:
            console.print(
                Panel(
                    "[bold]Tiến trình bị inject:[/bold] "
                    + ", ".join(escape(p) for p in procs.injected_processes)
                    + "\n"
                    f"[bold]Files dropped:[/bold] {len(procs.dropped_files)}\n"
                    f"[bold]Registry keys:[/bold] {len(procs.registry_keys)}\n"
                    f"[bold]Mutexes:[/bold] {len(procs.mutexes)}",
                    title="[bold yellow]⚙️  Hoạt động hệ thống[/bold yellow]",
                    border_style="yellow",
                )
            )

    def print_playbook(self, playbook: IncidentResponsePlaybook) -> None:
        console.print()
        console.print(
            Rule(f"[bold green]╔ QUY TRÌNH PHẢN ỨNG SỰ CỐ - {playbook.malware_name} ╗[/bold green]", style="green")
        )

        style = _SEVERITY_STYLE.get(playbook.severity, "white")
        console.print(
            Panel(
                f"[bold]Tóm tắt:[/bold] {playbook.summary}\n\n"
                f"[bold]Biện pháp ưu tiên:[/bold] {playbook.mitigation_summary}",
                title=f"[{style}]🚨 MỨC ĐỘ: {playbook.severity}[/{style}]",
                border_style=style.replace("bold ", ""),
            )
        )

        # Group actions by phase
        phase_map: dict = {}
        for action in playbook.actions:
            phase_map.setdefault(action.phase, []).append(action)

        for phase, acts in phase_map.items():
            console.print(f"\n[bold cyan]{'─'*60}[/bold cyan]")
            console.print(f"[bold cyan]📌 {phase}[/bold cyan]")
            for action in acts:
                lbl, color = _PRIORITY_LABEL.get(action.priority, ("", "white"))
                console.print(f"\n  [{color}]{lbl}[/{color}] [bold]{escape(action.title)}[/bold]")
                console.print(f"  [dim]{action.category}[/dim]")
                console.print(
                    f"  [dim]Owner: {escape(action.owner or 'N/A')} | SLA: {escape(action.sla or 'N/A')} | Status: {escape(action.status)}[/dim]"
                )
                console.print(f"  {escape(action.description)}")
                if action.commands:
                    console.print("  [bold]Lệnh thực thi:[/bold]")
                    for cmd in action.commands:
                        if cmd.startswith("#") or not cmd.strip():
                            console.print(f"  [dim]{escape(cmd)}[/dim]")
                        else:
                            console.print(f"  [green]  $ {escape(cmd)}[/green]")
                if action.notes:
                    console.print("  [bold]Ghi chú:[/bold]")
                    for note in action.notes:
                        console.print(f"  [yellow]  • {escape(note)}[/yellow]")
                if action.evidence_required:
                    console.print("  [bold]Bằng chứng cần lưu:[/bold]")
                    for item in action.evidence_required:
                        console.print(f"  [cyan]  • {escape(item)}[/cyan]")

        # IOC summary table
        console.print()
        ioc_table = Table(
            title="📋 IOC Blocklist Tổng hợp", box=box.ROUNDED, border_style="cyan", header_style="bold cyan"
        )
        ioc_table.add_column("Loại IOC", style="bold")
        ioc_table.add_column("Số lượng", justify="center")
        ioc_table.add_column("Mẫu", style="dim")
        bl = playbook.ioc_blocklist
        ioc_table.add_row(
            "IP Addresses", str(len(bl.get("ip_addresses", []))), ", ".join(bl.get("ip_addresses", [])[:3])
        )
        ioc_table.add_row("Domains", str(len(bl.get("domains", []))), ", ".join(bl.get("domains", [])[:2]))
        ioc_table.add_row(
            "URLs", str(len(bl.get("urls", []))), (bl.get("urls", [""])[0][:50] if bl.get("urls") else "")
        )
        ioc_table.add_row("File Hashes", str(len(bl.get("file_hashes", []))), "")
        ioc_table.add_row("Filenames", str(len(bl.get("filenames", []))), ", ".join(bl.get("filenames", [])[:3]))
        console.print(ioc_table)
        console.print()


# ─────────────────────────────────────────────────────────────────────────────
# File exporters
# ─────────────────────────────────────────────────────────────────────────────


def _uniq(values: list[Any]) -> list[Any]:
    seen = set()
    out = []
    for value in values:
        key = json.dumps(value, ensure_ascii=False, sort_keys=True) if isinstance(value, dict) else str(value)
        if key and key not in seen:
            seen.add(key)
            out.append(value)
    return out


def _technique_ids(result: MalwareAnalysisResult) -> set[str]:
    return {str(t.get("id", "")).upper() for t in result.threat_info.mitre_techniques if t.get("id")}


def _technique_names(result: MalwareAnalysisResult, tactic: str = "") -> list[str]:
    names = []
    for item in result.threat_info.mitre_techniques:
        if tactic and str(item.get("tactic", "")).lower() != tactic.lower():
            continue
        text = f"{item.get('id', '')} - {item.get('name', '')}".strip(" -")
        if text:
            names.append(text)
    return names


def _build_behavior_narrative(result: MalwareAnalysisResult) -> list[str]:
    ids = _technique_ids(result)
    procs = result.processes
    net = result.network
    parts = []

    if any(t.startswith("T1566") for t in ids):
        parts.append(
            "Dấu hiệu truy cập ban đầu là phishing/attachment theo MITRE T1566; cần đối chiếu email gateway để tìm thư đã phát tán mẫu."
        )
    if any(t.startswith(("T1059", "T1204")) for t in ids):
        names = ", ".join(p.get("name", "") for p in procs.processes[:5] if p.get("name"))
        parts.append(
            f"Sau khi được kích hoạt, mẫu thực thi lệnh hoặc script trên Windows; process liên quan quan sát được: {names or 'chưa đủ dữ liệu process'}."
        )
    if procs.injected_processes or any(t.startswith("T1055") for t in ids):
        targets = ", ".join(procs.injected_processes[:5]) or "process hợp lệ của Windows"
        parts.append(
            f"Mã độc có dấu hiệu né tránh/phòng thủ bằng process injection vào {targets}, giúp che giấu hành vi dưới tiến trình tin cậy."
        )
    if any(t.startswith("T1547") for t in ids) or procs.registry_keys:
        parts.append(
            f"Cơ chế duy trì hiện diện được thể hiện qua {len(procs.registry_keys)} registry key/autostart artifact; cần kiểm tra Run/RunOnce/Startup/Scheduled Task."
        )
    discovery = _technique_names(result, "Discovery")
    if discovery:
        parts.append(
            f"Mẫu thực hiện trinh sát hệ thống ({'; '.join(discovery[:4])}) để thu thập thông tin máy, process, thư mục hoặc cấu hình mạng."
        )
    if net.ip_addresses or net.domains or net.urls:
        parts.append(
            f"Mẫu có hoạt động C2/tải payload qua mạng: {len(net.ip_addresses)} IP, {len(net.domains)} domain và {len(net.urls)} URL được ghi nhận."
        )
    if any(t.startswith(("T1041", "T1056", "T1555")) for t in ids):
        parts.append(
            "Có chỉ dấu đánh cắp hoặc gửi dữ liệu ra ngoài; cần kiểm tra proxy/DNS/EDR để xác nhận dữ liệu nào đã rời khỏi máy."
        )
    if any(t.startswith("T1486") for t in ids):
        parts.append(
            "Có hành vi ransomware/mã hóa dữ liệu; ưu tiên cô lập máy và bảo vệ backup offline trước khi phục hồi."
        )

    if not parts:
        parts.append(
            "Báo cáo Any.Run chưa đủ tín hiệu để dựng toàn bộ chuỗi hành vi; phần dưới liệt kê các IOC và artifact đã quan sát được."
        )
    return parts


def _build_spread_analysis(result: MalwareAnalysisResult) -> list[str]:
    ids = _technique_ids(result)
    file = result.file_info
    net = result.network
    out = []

    if any(t.startswith("T1566") for t in ids):
        out.append("Vector lây nhiễm ban đầu nhiều khả năng là email phishing có đính kèm hoặc liên kết độc hại.")
    if file and any(ext in file.name.lower() for ext in (".doc", ".docm", ".xls", ".xlsm", ".rtf")):
        out.append(
            f"File đầu vào `{file.name}` là tài liệu Office/RTF, phù hợp kịch bản người dùng mở file rồi macro/script tải payload kế tiếp."
        )
    if any(t.startswith(("T1210", "T1021", "T1133")) for t in ids):
        out.append(
            "Có dấu hiệu kỹ thuật lateral movement/remote service; cần săn tìm host khác có cùng IOC trong log nội bộ."
        )
    if any(ind in " ".join(net.urls + net.domains).lower() for ind in ("payload", "download", "update", "cdn")):
        out.append(
            "Các URL/domain có mẫu tên như payload/update/cdn cho thấy malware có thể tải stage tiếp theo từ hạ tầng ngoài."
        )
    if any(t.startswith("T1486") for t in ids):
        out.append(
            "Với ransomware, nguy cơ lan truyền trong mạng nội bộ cao hơn nếu máy có SMB/share/credential dùng chung."
        )
    if not out:
        out.append(
            "Chưa thấy bằng chứng tự lây lan rõ ràng trong dữ liệu sandbox; cần kiểm tra email, proxy, SMB, VPN và EDR để xác định phạm vi thật."
        )
    return out


def _build_origin_analysis(result: MalwareAnalysisResult) -> list[str]:
    file = result.file_info
    net = result.network
    out = []

    if file:
        out.append(
            f"Nguồn quan sát trực tiếp là mẫu được gửi vào sandbox: `{file.name}` ({file.file_type or 'chưa rõ loại file'}), SHA256 `{file.sha256 or 'N/A'}`."
        )
    if net.urls:
        out.append(
            f"Hạ tầng liên quan gồm các URL đầu tiên: {', '.join(f'`{u}`' for u in net.urls[:3])}. Đây là nơi mẫu liên lạc hoặc tải nội dung trong phiên phân tích."
        )
    if net.domains:
        out.append(
            f"Domain liên quan: {', '.join(f'`{d}`' for d in net.domains[:5])}. Cần tra WHOIS/passive DNS/threat intel để xác định chủ thể vận hành."
        )
    if not out:
        out.append(
            "Báo cáo hiện chưa có thông tin nguồn gốc ngoài mẫu phân tích; chưa thể kết luận quốc gia, nhóm tấn công hoặc chiến dịch nếu không có threat intelligence bổ sung."
        )
    else:
        out.append(
            "Lưu ý: sandbox chỉ chứng minh nguồn/hạ tầng quan sát được trong phiên chạy, không đủ để quy kết quốc gia hoặc nhóm APT nếu thiếu threat intelligence độc lập."
        )
    return out


def _build_affected_files(result: MalwareAnalysisResult) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    if result.file_info:
        rows.append(
            {
                "role": "Mẫu đầu vào",
                "name": result.file_info.name,
                "sha256": result.file_info.sha256,
                "type": result.file_info.file_type,
            }
        )
    for item in result.processes.dropped_files:
        rows.append(
            {
                "role": "File được drop/tạo mới",
                "name": item.get("name", ""),
                "sha256": item.get("sha256", ""),
                "type": item.get("type", ""),
            }
        )
    for filename in result.iocs.filenames:
        if filename and not any(r["name"] == filename for r in rows):
            rows.append(
                {
                    "role": "Tên file IOC",
                    "name": filename,
                    "sha256": "",
                    "type": "",
                }
            )
    return _uniq(rows)


def build_malware_analysis(result: MalwareAnalysisResult) -> dict[str, Any]:
    return {
        "behavior": _build_behavior_narrative(result),
        "spread": _build_spread_analysis(result),
        "affected_files": _build_affected_files(result),
        "origin": _build_origin_analysis(result),
    }


def build_ir_evaluation(result: MalwareAnalysisResult, playbook: IncidentResponsePlaybook) -> dict[str, Any]:
    blocklist = playbook.ioc_blocklist
    ioc_count = sum(len(blocklist.get(key, []) or []) for key in ("ip_addresses", "domains", "urls", "file_hashes", "filenames"))
    action_count = len(playbook.actions)
    evidence_ready = sum(1 for action in playbook.actions if action.evidence_required)
    owner_ready = sum(1 for action in playbook.actions if action.owner and action.sla)
    coverage_points = [
        bool(result.threat_info.mitre_techniques),
        ioc_count > 0,
        bool(playbook.timeline),
        bool(playbook.scope_hunting),
        evidence_ready == action_count if action_count else False,
        owner_ready == action_count if action_count else False,
    ]
    readiness = round((sum(1 for point in coverage_points if point) / len(coverage_points)) * 100)
    detection_outputs = ["IOC CSV", "Splunk SPL", "Elastic KQL", "Microsoft Sentinel KQL", "Sigma", "Suricata", "STIX 2.1"]
    gaps = []
    if not result.threat_info.mitre_techniques:
        gaps.append("Chưa có MITRE technique để giải thích TTP.")
    if not ioc_count:
        gaps.append("Chưa có IOC để block/hunt.")
    if not playbook.scope_hunting:
        gaps.append("Chưa có truy vấn hunting để xác định phạm vi.")
    if readiness < 100:
        gaps.append("Cần đối chiếu log thật để xác nhận phạm vi ảnh hưởng.")

    return {
        "readiness_score": readiness,
        "ioc_count": ioc_count,
        "mitre_count": len(result.threat_info.mitre_techniques),
        "action_count": action_count,
        "timeline_steps": len(playbook.timeline),
        "hunting_queries": len(playbook.scope_hunting),
        "actions_with_owner_sla": owner_ready,
        "actions_with_evidence": evidence_ready,
        "detection_outputs": detection_outputs,
        "gaps": gaps or ["Đủ dữ liệu cho demo IR; vẫn cần xác minh trên log thật trước khi kết luận sản xuất."],
    }


def _report_payload(
    result: MalwareAnalysisResult,
    playbook: IncidentResponsePlaybook,
) -> dict[str, Any]:
    return {
        "generated_at": datetime.datetime.now().isoformat(),
        "task_uuid": result.task_uuid,
        "analysis_url": result.analysis_url,
        "os_env": result.os_env,
        "duration": result.duration_seconds,
        "file": (
            {
                "name": result.file_info.name,
                "size": result.file_info.size,
                "type": result.file_info.file_type,
                "md5": result.file_info.md5,
                "sha1": result.file_info.sha1,
                "sha256": result.file_info.sha256,
            }
            if result.file_info
            else None
        ),
        "threat": {
            "verdict": result.threat_info.verdict,
            "threat_level": result.threat_info.threat_level,
            "threat_name": result.threat_info.threat_name,
            "tags": result.threat_info.tags,
            "mitre": result.threat_info.mitre_techniques,
        },
        "network": {
            "ips": result.network.ip_addresses,
            "domains": result.network.domains,
            "urls": result.network.urls,
            "http": result.network.http_requests,
            "dns": result.network.dns_queries,
        },
        "processes": {
            "list": result.processes.processes,
            "injected": result.processes.injected_processes,
            "dropped": result.processes.dropped_files,
            "registry": result.processes.registry_keys,
            "mutexes": result.processes.mutexes,
        },
        "malware_analysis": build_malware_analysis(result),
        "ir_evaluation": build_ir_evaluation(result, playbook),
        "playbook": {
            "malware_name": playbook.malware_name,
            "severity": playbook.severity,
            "threat_level": playbook.threat_level,
            "summary": playbook.summary,
            "mitigation": playbook.mitigation_summary,
            "actions": [
                {
                    "priority": a.priority,
                    "phase": a.phase,
                    "category": a.category,
                    "title": a.title,
                    "description": a.description,
                    "commands": a.commands,
                    "notes": a.notes,
                    "owner": a.owner,
                    "sla": a.sla,
                    "evidence_required": a.evidence_required,
                    "status": a.status,
                }
                for a in playbook.actions
            ],
            "ioc_blocklist": playbook.ioc_blocklist,
            "severity_score": playbook.severity_score,
            "timeline": playbook.timeline,
            "scope_hunting": playbook.scope_hunting,
        },
    }


def _html(value: Any) -> str:
    return html.escape(str(value or ""), quote=True)


def _html_list(items: list[Any], empty: str = "Không có dữ liệu") -> str:
    if not items:
        return f'<p class="muted">{_html(empty)}</p>'
    return "<ul>" + "".join(f"<li>{_html(item)}</li>" for item in items) + "</ul>"


def _html_tags(items: list[Any], css_class: str = "") -> str:
    if not items:
        return '<span class="muted">Không có</span>'
    return "".join(f'<span class="tag {css_class}">{_html(item)}</span>' for item in items)


def build_html_report(data: dict[str, Any]) -> str:
    """Build a self-contained HTML incident response report from an app payload."""
    threat = data.get("threat", {}) or {}
    playbook = data.get("playbook", {}) or {}
    file_info = data.get("file") or {}
    malware_analysis = data.get("malware_analysis", {}) or {}
    ir_evaluation = data.get("ir_evaluation", {}) or {}
    blocklist = playbook.get("ioc_blocklist", {}) or {}
    actions = playbook.get("actions", []) or []
    severity = str(playbook.get("severity", "UNKNOWN")).upper()
    severity_class = severity.lower() if severity.lower() in {"critical", "high", "medium", "low"} else "unknown"

    mitre_rows = "".join(
        "<tr>"
        f"<td>{_html(item.get('id'))}</td>"
        f"<td>{_html(item.get('name'))}</td>"
        f"<td>{_html(item.get('tactic'))}</td>"
        "</tr>"
        for item in threat.get("mitre", []) or []
    )
    affected_rows = "".join(
        "<tr>"
        f"<td>{_html(item.get('role'))}</td>"
        f"<td>{_html(item.get('name'))}</td>"
        f"<td class=\"mono\">{_html(item.get('sha256') or 'N/A')}</td>"
        f"<td>{_html(item.get('type') or 'N/A')}</td>"
        "</tr>"
        for item in malware_analysis.get("affected_files", []) or []
    )
    score = playbook.get("severity_score", {}) or {}
    timeline_rows = "".join(
        "<tr>"
        f"<td>{_html(item.get('step'))}</td>"
        f"<td>{_html(item.get('stage'))}</td>"
        f"<td>{_html(item.get('event'))}</td>"
        f"<td class=\"mono\">{_html(item.get('evidence'))}</td>"
        f"<td>{_html(item.get('mitre') or 'N/A')}</td>"
        f"<td>{_html(item.get('ir_action'))}</td>"
        "</tr>"
        for item in playbook.get("timeline", []) or []
    )
    hunt_rows = "".join(
        "<tr>"
        f"<td>{_html(item.get('priority'))}</td>"
        f"<td>{_html(item.get('data_source'))}</td>"
        f"<td>{_html(item.get('question'))}</td>"
        f"<td><pre>{_html(item.get('query'))}</pre></td>"
        f"<td>{_html(item.get('evidence'))}</td>"
        "</tr>"
        for item in playbook.get("scope_hunting", []) or []
    )
    action_html = "".join(
        '<section class="action">'
        f"<div class=\"priority\">P{_html(action.get('priority'))}</div>"
        f"<h3>{_html(action.get('title'))}</h3>"
        f"<p class=\"muted\">{_html(action.get('phase'))} · {_html(action.get('category'))}</p>"
        f"<p class=\"muted\"><strong>Owner:</strong> {_html(action.get('owner') or 'N/A')} · <strong>SLA:</strong> {_html(action.get('sla') or 'N/A')} · <strong>Status:</strong> {_html(action.get('status') or 'pending')}</p>"
        f"<p>{_html(action.get('description'))}</p>"
        + (
            "<pre>" + "\n".join(_html(command) for command in action.get("commands", []) or []) + "</pre>"
            if action.get("commands")
            else ""
        )
        + _html_list(action.get("notes", []) or [], empty="")
        + ("<p><strong>Bằng chứng cần lưu:</strong></p>" + _html_list(action.get("evidence_required", []) or [], empty="") if action.get("evidence_required") else "")
        + "</section>"
        for action in actions
    )

    return f"""<!doctype html>
<html lang="vi">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>IR Report - {_html(playbook.get("malware_name", "Malware"))}</title>
  <style>
    body {{ font-family: Arial, sans-serif; color: #18212f; margin: 0; background: #f5f7fb; }}
    main {{ max-width: 1080px; margin: 0 auto; padding: 32px 24px 56px; }}
    header {{ background: #111827; color: white; padding: 28px; border-radius: 10px; margin-bottom: 22px; }}
    h1 {{ margin: 0 0 10px; font-size: 28px; }}
    h2 {{ margin-top: 28px; border-bottom: 2px solid #d8dee9; padding-bottom: 8px; }}
    h3 {{ margin: 0 0 6px; }}
    .summary {{ font-size: 15px; line-height: 1.65; }}
    .badge {{ display: inline-block; padding: 6px 12px; border-radius: 999px; font-weight: 700; }}
    .critical {{ background: #fee2e2; color: #b91c1c; }}
    .high {{ background: #ffedd5; color: #c2410c; }}
    .medium {{ background: #fef3c7; color: #b45309; }}
    .low {{ background: #dcfce7; color: #15803d; }}
    .unknown {{ background: #e5e7eb; color: #374151; }}
    .grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }}
    .card {{ background: white; border: 1px solid #d8dee9; border-radius: 8px; padding: 16px; margin: 12px 0; }}
    .metric {{ color: #64748b; font-size: 12px; text-transform: uppercase; }}
    .metric strong {{ display: block; color: #0f172a; font-size: 22px; margin-top: 4px; }}
    .muted {{ color: #64748b; }}
    .mono, pre {{ font-family: Consolas, monospace; }}
    table {{ border-collapse: collapse; width: 100%; background: white; }}
    th, td {{ border: 1px solid #d8dee9; padding: 9px 10px; text-align: left; vertical-align: top; }}
    th {{ background: #eef2f7; }}
    .tag {{ display: inline-block; background: #e0f2fe; color: #075985; padding: 4px 8px; border-radius: 5px; margin: 3px; font-family: Consolas, monospace; font-size: 12px; }}
    .tag.domain {{ background: #ffedd5; color: #9a3412; }}
    .tag.hash {{ background: #ede9fe; color: #5b21b6; }}
    .action {{ background: white; border-left: 5px solid #2563eb; border-radius: 8px; padding: 14px 16px; margin: 12px 0; box-shadow: 0 1px 3px rgba(15, 23, 42, 0.08); }}
    .priority {{ float: right; font-weight: 700; color: #2563eb; }}
    pre {{ white-space: pre-wrap; background: #0f172a; color: #bbf7d0; padding: 12px; border-radius: 6px; overflow-x: auto; }}
    @media print {{ body {{ background: white; }} main {{ padding: 0; }} header, .card, .action {{ break-inside: avoid; }} }}
  </style>
</head>
<body>
<main>
  <header>
    <span class="badge {severity_class}">{_html(severity)}</span>
    <h1>Báo Cáo Phản Ứng Sự Cố - {_html(playbook.get("malware_name", "Unknown"))}</h1>
    <p class="summary">{_html(playbook.get("summary", ""))}</p>
    <p class="muted">Task: {_html(data.get("task_uuid"))} · OS: {_html(data.get("os_env"))} · Duration: {_html(data.get("duration"))}s</p>
  </header>

  <section class="grid">
    <div class="card"><div class="metric">Threat Level<strong>{_html(threat.get("threat_level"))}/4</strong></div></div>
    <div class="card"><div class="metric">MITRE Techniques<strong>{len(threat.get("mitre", []) or [])}</strong></div></div>
    <div class="card"><div class="metric">IOC Count<strong>{len(blocklist.get("ip_addresses", []) or []) + len(blocklist.get("domains", []) or []) + len(blocklist.get("file_hashes", []) or [])}</strong></div></div>
  </section>
  <section class="grid">
    <div class="card"><div class="metric">Risk Score<strong>{_html(score.get("score", "N/A"))}/100</strong></div></div>
    <div class="card"><div class="metric">Recommended Severity<strong>{_html(score.get("recommended_severity", "N/A"))}</strong></div></div>
    <div class="card"><div class="metric">Hunting Queries<strong>{len(playbook.get("scope_hunting", []) or [])}</strong></div></div>
  </section>
  <section class="grid">
    <div class="card"><div class="metric">IR Readiness<strong>{_html(ir_evaluation.get("readiness_score", "N/A"))}%</strong></div></div>
    <div class="card"><div class="metric">IR Actions<strong>{_html(ir_evaluation.get("action_count", len(actions)))}</strong></div></div>
    <div class="card"><div class="metric">Detection Outputs<strong>{len(ir_evaluation.get("detection_outputs", []) or [])}</strong></div></div>
  </section>

  <h2>1. Tổng Quan</h2>
  <div class="card">
    <p><strong>Verdict:</strong> {_html(threat.get("verdict"))}</p>
    <p><strong>Threat name:</strong> {_html(threat.get("threat_name") or playbook.get("malware_name"))}</p>
    <p><strong>Tags:</strong> {_html(", ".join(threat.get("tags", []) or []))}</p>
    <p><strong>Any.Run:</strong> <a href="{_html(data.get("analysis_url"))}">{_html(data.get("analysis_url"))}</a></p>
  </div>

  <h2>2. File & Hành Vi</h2>
  <div class="card">
    <p><strong>File:</strong> {_html(file_info.get("name", "N/A"))}</p>
    <p><strong>Type:</strong> {_html(file_info.get("type", "N/A"))}</p>
    <p><strong>SHA256:</strong> <span class="mono">{_html(file_info.get("sha256", "N/A"))}</span></p>
  </div>
  <div class="card">
    <h3>Cách mã độc hoạt động</h3>
    {_html_list(malware_analysis.get("behavior", []) or [])}
    <h3>Cách lây lan / vector xâm nhập</h3>
    {_html_list(malware_analysis.get("spread", []) or [])}
  </div>

  <h2>3. MITRE ATT&CK</h2>
  <table><thead><tr><th>ID</th><th>Technique</th><th>Tactic</th></tr></thead><tbody>{mitre_rows}</tbody></table>

  <h2>4. IOC Blocklist</h2>
  <div class="card">
    <h3>IP Addresses</h3>{_html_tags(blocklist.get("ip_addresses", []) or [])}
    <h3>Domains</h3>{_html_tags(blocklist.get("domains", []) or [], "domain")}
    <h3>File Hashes</h3>{_html_tags(blocklist.get("file_hashes", []) or [], "hash")}
  </div>

  <h2>5. Affected Files</h2>
  <table><thead><tr><th>Vai trò</th><th>File</th><th>SHA256</th><th>Loại</th></tr></thead><tbody>{affected_rows}</tbody></table>

  <h2>6. Timeline Điều Tra</h2>
  <table><thead><tr><th>Bước</th><th>Giai đoạn</th><th>Sự kiện</th><th>Bằng chứng</th><th>MITRE</th><th>Hành động IR</th></tr></thead><tbody>{timeline_rows}</tbody></table>

  <h2>7. Scope & Threat Hunting</h2>
  <table><thead><tr><th>Ưu tiên</th><th>Nguồn log</th><th>Câu hỏi</th><th>Query</th><th>Bằng chứng</th></tr></thead><tbody>{hunt_rows}</tbody></table>

  <h2>8. IR Playbook</h2>
  <div class="card"><strong>Biện pháp ưu tiên:</strong> {_html(playbook.get("mitigation", ""))}</div>
  {action_html}
</main>
</body>
</html>
"""


def _pdf_literal(text: Any) -> str:
    value = str(text or "").replace("\r", " ").replace("\n", " ")
    value = value.encode("latin-1", errors="replace").decode("latin-1")
    value = value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    return f"({value})"


def _simple_pdf_lines(data: dict[str, Any]) -> list[str]:
    threat = data.get("threat", {}) or {}
    playbook = data.get("playbook", {}) or {}
    blocklist = playbook.get("ioc_blocklist", {}) or {}
    lines = [
        f"Incident Response Report - {playbook.get('malware_name', 'Unknown')}",
        f"Severity: {playbook.get('severity', 'UNKNOWN')} | Threat Level: {threat.get('threat_level', 'N/A')}/4",
        f"Task UUID: {data.get('task_uuid', '')}",
        f"Any.Run: {data.get('analysis_url', '')}",
        f"OS: {data.get('os_env', '')}",
        "",
        "Summary:",
        playbook.get("summary", ""),
        "",
        "IOC Blocklist:",
        "IPs: " + ", ".join(blocklist.get("ip_addresses", [])[:20]),
        "Domains: " + ", ".join(blocklist.get("domains", [])[:20]),
        "Hashes: " + ", ".join(blocklist.get("file_hashes", [])[:10]),
        "",
        "Priority Actions:",
    ]
    for action in (playbook.get("actions", []) or [])[:12]:
        lines.extend(
            [
                f"P{action.get('priority')} - {action.get('title')}",
                action.get("description", ""),
            ]
        )
        if action.get("commands"):
            lines.append("Commands: " + " | ".join(action.get("commands", [])[:4]))
    wrapped = []
    for line in lines:
        wrapped.extend(textwrap.wrap(str(line), width=95) or [""])
    return wrapped


def _export_simple_pdf(data: dict[str, Any], filename: str | Path) -> Path:
    path = Path(filename)
    path.parent.mkdir(parents=True, exist_ok=True)
    content_lines = ["BT", "/F1 10 Tf", "14 TL", "50 790 Td"]
    for line in _simple_pdf_lines(data)[:54]:
        content_lines.append(f"{_pdf_literal(line)} Tj")
        content_lines.append("T*")
    content_lines.append("ET")
    stream = "\n".join(content_lines).encode("latin-1", errors="replace")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>"
        ),
        b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]

    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode("ascii"))
        output.extend(obj)
        output.extend(b"\nendobj\n")
    xref_offset = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        (f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n" f"startxref\n{xref_offset}\n%%EOF\n").encode("ascii")
    )
    path.write_bytes(bytes(output))
    return path


def _register_pdf_fonts() -> dict[str, str]:
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    font_sets = [
        {
            "normal": Path(r"C:\Windows\Fonts\arial.ttf"),
            "bold": Path(r"C:\Windows\Fonts\arialbd.ttf"),
            "italic": Path(r"C:\Windows\Fonts\ariali.ttf"),
            "bold_italic": Path(r"C:\Windows\Fonts\arialbi.ttf"),
        },
        {
            "normal": Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
            "bold": Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
            "italic": Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Oblique.ttf"),
            "bold_italic": Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-BoldOblique.ttf"),
        },
    ]
    selected = next((font_set for font_set in font_sets if all(path.is_file() for path in font_set.values())), None)
    if not selected:
        return {
            "normal": "Helvetica",
            "bold": "Helvetica-Bold",
            "italic": "Helvetica-Oblique",
            "bold_italic": "Helvetica-BoldOblique",
        }

    names = {
        "normal": "IRUnicode",
        "bold": "IRUnicode-Bold",
        "italic": "IRUnicode-Italic",
        "bold_italic": "IRUnicode-BoldItalic",
    }
    for key, name in names.items():
        if name not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont(name, str(selected[key])))
    pdfmetrics.registerFontFamily(
        "IRUnicode",
        normal=names["normal"],
        bold=names["bold"],
        italic=names["italic"],
        boldItalic=names["bold_italic"],
    )
    return names


def export_payload_pdf(data: dict[str, Any], filename: str | Path) -> Path:
    """Export a compact PDF report from an app payload."""
    path = Path(filename)
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table as PdfTable, TableStyle
    except ModuleNotFoundError:
        return _export_simple_pdf(data, path)

    font_names = _register_pdf_fonts()
    styles = getSampleStyleSheet()
    for style in styles.byName.values():
        if not hasattr(style, "fontName"):
            continue
        default_name = style.fontName.lower()
        if "bold" in default_name and ("oblique" in default_name or "italic" in default_name):
            style.fontName = font_names["bold_italic"]
        elif "bold" in default_name:
            style.fontName = font_names["bold"]
        elif "oblique" in default_name or "italic" in default_name:
            style.fontName = font_names["italic"]
        else:
            style.fontName = font_names["normal"]
    story = []
    threat = data.get("threat", {}) or {}
    playbook = data.get("playbook", {}) or {}
    blocklist = playbook.get("ioc_blocklist", {}) or {}

    def add_para(text: str, style: str = "BodyText") -> None:
        story.append(Paragraph(html.escape(str(text or "")), styles[style]))

    story.append(
        Paragraph(
            f"Incident Response Report - {html.escape(str(playbook.get('malware_name', 'Unknown')))}", styles["Title"]
        )
    )
    add_para(f"Severity: {playbook.get('severity', 'UNKNOWN')} | Threat Level: {threat.get('threat_level', 'N/A')}/4")
    add_para(playbook.get("summary", ""))
    story.append(Spacer(1, 12))

    meta_rows = [
        ["Task UUID", data.get("task_uuid", "")],
        ["Any.Run", data.get("analysis_url", "")],
        ["OS", data.get("os_env", "")],
        ["Verdict", threat.get("verdict", "")],
    ]
    table = PdfTable(meta_rows, colWidths=[100, 370])
    table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
                ("FONTNAME", (0, 0), (-1, -1), font_names["normal"]),
            ]
        )
    )
    story.extend([table, Spacer(1, 12)])

    story.append(Paragraph("MITRE ATT&amp;CK", styles["Heading2"]))
    mitre_rows = [["ID", "Technique", "Tactic"]] + [
        [item.get("id", ""), item.get("name", ""), item.get("tactic", "")] for item in threat.get("mitre", [])[:20]
    ]
    mitre_table = PdfTable(mitre_rows, colWidths=[70, 250, 150])
    mitre_table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("FONTNAME", (0, 0), (-1, -1), font_names["normal"]),
                ("FONTNAME", (0, 0), (-1, 0), font_names["bold"]),
            ]
        )
    )
    story.extend([mitre_table, Spacer(1, 12)])

    story.append(Paragraph("IOC Blocklist", styles["Heading2"]))
    add_para("IPs: " + ", ".join(blocklist.get("ip_addresses", [])[:20]))
    add_para("Domains: " + ", ".join(blocklist.get("domains", [])[:20]))
    add_para("Hashes: " + ", ".join(blocklist.get("file_hashes", [])[:10]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Priority Actions", styles["Heading2"]))
    for action in (playbook.get("actions", []) or [])[:12]:
        add_para(f"P{action.get('priority')} - {action.get('title')}", "Heading3")
        add_para(action.get("description", ""))
        if action.get("commands"):
            add_para("Commands: " + " | ".join(action.get("commands", [])[:4]))

    doc = SimpleDocTemplate(str(path), pagesize=A4, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    doc.build(story)
    return path


class ReportExporter:
    """Xuất báo cáo ra file Markdown và JSON."""

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

    def export_markdown(
        self,
        result: MalwareAnalysisResult,
        playbook: IncidentResponsePlaybook,
    ) -> Path:
        now = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.output_dir / f"IR_Report_{now}.md"

        threat = result.threat_info
        file = result.file_info
        net = result.network
        procs = result.processes

        lines = [
            f"# Báo Cáo Phản Ứng Sự Cố Mã Độc",
            f"",
            f"> **Thời gian tạo:** {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}  ",
            f"> **Mức độ:** `{playbook.severity}`  ",
            f"> **Any.Run Task:** [{result.task_uuid}]({result.analysis_url})",
            f"",
            f"---",
            f"",
            f"## 1. Tổng Quan Mã Độc",
            f"",
            f"| Thuộc tính | Giá trị |",
            f"|---|---|",
            f"| Tên mã độc | {playbook.malware_name} |",
            f"| Verdict | {threat.verdict} |",
            f"| Threat Level | {threat.threat_level}/4 |",
            f"| Môi trường | {result.os_env} |",
            f"| Thời gian phân tích | {result.duration_seconds}s |",
            f"",
        ]

        if file:
            lines += [
                f"### Thông Tin File",
                f"",
                f"| Thuộc tính | Giá trị |",
                f"|---|---|",
                f"| Tên file | `{file.name}` |",
                f"| Loại file | {file.file_type} |",
                f"| Kích thước | {file.size:,} bytes |",
                f"| MD5 | `{file.md5}` |",
                f"| SHA1 | `{file.sha1}` |",
                f"| SHA256 | `{file.sha256}` |",
                f"",
            ]

        malware_analysis = build_malware_analysis(result)
        lines += [
            f"## 2. Phân Tích Chi Tiết Mã Độc",
            f"",
            f"### Cách mã độc hoạt động",
            *[f"- {item}" for item in malware_analysis["behavior"]],
            f"",
            f"### Cách lây lan / vector xâm nhập",
            *[f"- {item}" for item in malware_analysis["spread"]],
            f"",
            f"### File bị nhiễm hoặc bị tạo/drop",
            f"",
            f"| Vai trò | File | SHA256 | Loại |",
            f"|---|---|---|---|",
            *[
                f"| {row['role']} | `{row['name']}` | `{row['sha256'] or 'N/A'}` | {row['type'] or 'N/A'} |"
                for row in malware_analysis["affected_files"]
            ],
            f"",
            f"### Nguồn gốc và hạ tầng liên quan",
            *[f"- {item}" for item in malware_analysis["origin"]],
            f"",
        ]

        if threat.mitre_techniques:
            lines += [
                f"## 3. MITRE ATT&CK Techniques",
                f"",
                f"| ID | Tên kỹ thuật | Tactic |",
                f"|---|---|---|",
                *[f"| {t['id']} | {t['name']} | {t['tactic']} |" for t in threat.mitre_techniques],
                f"",
            ]

        lines += [
            f"## 4. Hoạt Động Mạng",
            f"",
            f"### IP Addresses ({len(net.ip_addresses)})",
            *[f"- `{ip}`" for ip in net.ip_addresses],
            f"",
            f"### Domains ({len(net.domains)})",
            *[f"- `{d}`" for d in net.domains],
            f"",
        ]

        if net.urls:
            lines += [
                f"### URLs ({len(net.urls)})",
                *[f"- `{u}`" for u in net.urls[:20]],
                f"",
            ]

        lines += [
            f"## 5. Hoạt Động Hệ Thống",
            f"",
            f"- **Tiến trình bị inject:** {', '.join(procs.injected_processes) or 'Không có'}",
            f"- **Files đã drop:** {len(procs.dropped_files)}",
            f"- **Registry keys:** {len(procs.registry_keys)}",
            f"- **Mutexes:** {len(procs.mutexes)}",
            f"",
        ]

        if procs.dropped_files:
            lines += [
                f"### Files Dropped",
                f"",
                f"| Tên file | SHA256 | Loại |",
                f"|---|---|---|",
                *[f"| `{f['name']}` | `{f['sha256'][:16]}...` | {f['type']} |" for f in procs.dropped_files[:10]],
                f"",
            ]

        lines += [
            f"## 6. Quy Trình Phản Ứng Sự Cố",
            f"",
            f"> {playbook.summary}",
            f"",
            f"### Đánh Giá Kết Quả Tự Động Hóa",
            f"",
            f"| Chỉ số | Giá trị |",
            f"|---|---|",
            f"| Readiness score | {build_ir_evaluation(result, playbook).get('readiness_score')}% |",
            f"| Tổng IOC | {build_ir_evaluation(result, playbook).get('ioc_count')} |",
            f"| MITRE techniques | {build_ir_evaluation(result, playbook).get('mitre_count')} |",
            f"| Hành động IR | {build_ir_evaluation(result, playbook).get('action_count')} |",
            f"| Hunting queries | {build_ir_evaluation(result, playbook).get('hunting_queries')} |",
            f"",
            f"### Ma Trận Đánh Giá Mức Độ",
            f"",
            f"| Thuộc tính | Giá trị |",
            f"|---|---|",
            f"| Điểm rủi ro nội bộ | {playbook.severity_score.get('score', 'N/A')}/100 |",
            f"| Mức đề xuất | {playbook.severity_score.get('recommended_severity', 'N/A')} |",
            f"| Mô hình | {playbook.severity_score.get('model', 'N/A')} |",
            f"",
            *[f"- {reason}" for reason in playbook.severity_score.get("reasons", [])],
            f"",
            f"### Timeline Điều Tra",
            f"",
            f"| Bước | Giai đoạn | Sự kiện | Bằng chứng | MITRE | Hành động IR |",
            f"|---|---|---|---|---|---|",
            *[
                f"| {row.get('step')} | {row.get('stage')} | {row.get('event')} | `{row.get('evidence')}` | {row.get('mitre') or 'N/A'} | {row.get('ir_action')} |"
                for row in playbook.timeline
            ],
            f"",
            f"### Scope & Threat Hunting",
            f"",
            f"| Ưu tiên | Nguồn log | Câu hỏi | Bằng chứng cần thu |",
            f"|---|---|---|---|",
            *[
                f"| {row.get('priority')} | {row.get('data_source')} | {row.get('question')} | {row.get('evidence')} |"
                for row in playbook.scope_hunting
            ],
            f"",
            f"**Biện pháp ưu tiên:** {playbook.mitigation_summary}",
            f"",
        ]

        phase_map: dict = {}
        for action in playbook.actions:
            phase_map.setdefault(action.phase, []).append(action)

        for phase, acts in phase_map.items():
            lines.append(f"### {phase}")
            lines.append("")
            for action in acts:
                pri_labels = {1: "🔴 P1-CRITICAL", 2: "🟠 P2-HIGH", 3: "🟡 P3-MEDIUM", 4: "🟢 P4-LOW"}
                lines.append(f"#### {pri_labels.get(action.priority,'')} – {action.title}")
                lines.append(f"")
                lines.append(f"**Danh mục:** {action.category}")
                lines.append(f"**Owner/SLA/Status:** {action.owner or 'N/A'} / {action.sla or 'N/A'} / {action.status}")
                lines.append(f"")
                lines.append(action.description)
                lines.append("")
                if action.commands:
                    lines.append("```powershell")
                    lines.extend(action.commands)
                    lines.append("```")
                    lines.append("")
                if action.notes:
                    for note in action.notes:
                        lines.append(f"> 💡 {note}")
                    lines.append("")
                if action.evidence_required:
                    lines.append("**Bằng chứng cần lưu:**")
                    for item in action.evidence_required:
                        lines.append(f"- {item}")
                    lines.append("")

        lines += [
            f"## 7. IOC Blocklist",
            f"",
            f"### IP Addresses",
            *[f"- `{ip}`" for ip in playbook.ioc_blocklist.get("ip_addresses", [])],
            f"",
            f"### Domains",
            *[f"- `{d}`" for d in playbook.ioc_blocklist.get("domains", [])],
            f"",
            f"### File Hashes",
            *[f"- `{h}`" for h in playbook.ioc_blocklist.get("file_hashes", [])],
            f"",
            f"---",
            f"*Báo cáo tự động được tạo bởi AnyRun-IR-Tool*",
        ]

        filename.write_text("\n".join(lines), encoding="utf-8")
        return filename

    def export_json(
        self,
        result: MalwareAnalysisResult,
        playbook: IncidentResponsePlaybook,
    ) -> Path:
        now = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.output_dir / f"IR_Report_{now}.json"

        payload = _report_payload(result, playbook)
        data = {
            "generated_at": payload["generated_at"],
            "task_uuid": payload["task_uuid"],
            "analysis_url": payload["analysis_url"],
            "severity": playbook.severity,
            "malware_name": playbook.malware_name,
            "summary": playbook.summary,
            "malware_analysis": payload["malware_analysis"],
            "ir_evaluation": payload["ir_evaluation"],
            "ioc_blocklist": playbook.ioc_blocklist,
            "severity_score": playbook.severity_score,
            "timeline": playbook.timeline,
            "scope_hunting": playbook.scope_hunting,
            "mitre_techniques": result.threat_info.mitre_techniques,
            "actions": payload["playbook"]["actions"],
        }
        filename.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        return filename

    def export_html(
        self,
        result: MalwareAnalysisResult,
        playbook: IncidentResponsePlaybook,
    ) -> Path:
        now = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.output_dir / f"IR_Report_{now}.html"
        filename.write_text(build_html_report(_report_payload(result, playbook)), encoding="utf-8")
        return filename

    def export_pdf(
        self,
        result: MalwareAnalysisResult,
        playbook: IncidentResponsePlaybook,
    ) -> Path:
        now = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.output_dir / f"IR_Report_{now}.pdf"
        return export_payload_pdf(_report_payload(result, playbook), filename)
