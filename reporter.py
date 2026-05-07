"""
reporter.py
~~~~~~~~~~~
In kết quả ra terminal (rich) và xuất file báo cáo (Markdown + PDF).
"""

from __future__ import annotations
import os
import json
import datetime
from pathlib import Path
from typing import Optional

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
    "HIGH":     "bold orange1",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold green",
    "UNKNOWN":  "dim",
}

_PRIORITY_LABEL = {
    1: ("[P1-CRITICAL]", "red"),
    2: ("[P2-HIGH]",     "orange1"),
    3: ("[P3-MEDIUM]",   "yellow"),
    4: ("[P4-LOW]",      "green"),
}


# ─────────────────────────────────────────────────────────────────────────────
# Terminal reporter
# ─────────────────────────────────────────────────────────────────────────────

class TerminalReporter:
    """In kết quả đẹp ra terminal bằng Rich."""

    def print_analysis(self, result: MalwareAnalysisResult) -> None:
        threat = result.threat_info
        style  = _SEVERITY_STYLE.get(
            "CRITICAL" if threat.threat_level >= 2 else
            ("MEDIUM"  if threat.threat_level == 1 else "LOW"),
            "white"
        )

        console.print()
        console.print(Rule("[bold cyan]╔ KẾT QUẢ PHÂN TÍCH ANY.RUN ╗[/bold cyan]", style="cyan"))

        # File info panel
        if result.file_info:
            f = result.file_info
            console.print(Panel(
                f"[bold]Tên file:[/bold] {escape(f.name)}\n"
                f"[bold]Loại:[/bold] {f.file_type} | [bold]MIME:[/bold] {f.mime_type}\n"
                f"[bold]Kích thước:[/bold] {f.size:,} bytes\n"
                f"[bold]MD5:[/bold]    [dim]{f.md5}[/dim]\n"
                f"[bold]SHA1:[/bold]   [dim]{f.sha1}[/dim]\n"
                f"[bold]SHA256:[/bold] [dim]{f.sha256}[/dim]",
                title="[bold blue]📄 Thông tin mẫu mã độc[/bold blue]",
                border_style="blue",
            ))

        # Threat verdict
        verdict_text = Text()
        verdict_text.append("● Kết luận: ", style="bold")
        verdict_text.append(threat.verdict, style=style + " bold")
        verdict_text.append(f"  (Threat Level {threat.threat_level}/4)", style="dim")
        console.print(Panel(
            f"{verdict_text}\n"
            f"[bold]Tên mã độc:[/bold] {escape(threat.threat_name or 'Chưa xác định')}\n"
            f"[bold]Tags:[/bold] {', '.join(threat.tags) or 'N/A'}\n"
            f"[bold]Môi trường:[/bold] {result.os_env}\n"
            f"[bold]Any.Run URL:[/bold] [link={result.analysis_url}]{result.analysis_url}[/link]",
            title="[bold red]⚠️  Mức độ đe dọa[/bold red]",
            border_style="red" if threat.threat_level >= 2 else "yellow",
        ))

        # MITRE table
        if threat.mitre_techniques:
            table = Table(title="🎯 MITRE ATT&CK Techniques", box=box.ROUNDED,
                          border_style="magenta", header_style="bold magenta")
            table.add_column("ID",     style="cyan",  no_wrap=True)
            table.add_column("Tên kỹ thuật", style="white")
            table.add_column("Tactic", style="yellow")
            for t in threat.mitre_techniques[:15]:
                table.add_row(t.get("id",""), t.get("name",""), t.get("tactic",""))
            console.print(table)

        # Network IOC table
        net = result.network
        if net.ip_addresses or net.domains:
            net_table = Table(title="🌐 Hoạt động mạng (C2)", box=box.SIMPLE_HEAD,
                              border_style="red", header_style="bold red")
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
            console.print(Panel(
                "[bold]Tiến trình bị inject:[/bold] " +
                ", ".join(escape(p) for p in procs.injected_processes) + "\n"
                f"[bold]Files dropped:[/bold] {len(procs.dropped_files)}\n"
                f"[bold]Registry keys:[/bold] {len(procs.registry_keys)}\n"
                f"[bold]Mutexes:[/bold] {len(procs.mutexes)}",
                title="[bold yellow]⚙️  Hoạt động hệ thống[/bold yellow]",
                border_style="yellow",
            ))

    def print_playbook(self, playbook: IncidentResponsePlaybook) -> None:
        console.print()
        console.print(Rule(
            f"[bold green]╔ QUY TRÌNH PHẢN ỨNG SỰ CỐ - {playbook.malware_name} ╗[/bold green]",
            style="green"
        ))

        style = _SEVERITY_STYLE.get(playbook.severity, "white")
        console.print(Panel(
            f"[bold]Tóm tắt:[/bold] {playbook.summary}\n\n"
            f"[bold]Biện pháp ưu tiên:[/bold] {playbook.mitigation_summary}",
            title=f"[{style}]🚨 MỨC ĐỘ: {playbook.severity}[/{style}]",
            border_style=style.replace("bold ", ""),
        ))

        # Group actions by phase
        phase_map: dict = {}
        for action in playbook.actions:
            phase_map.setdefault(action.phase, []).append(action)

        for phase, acts in phase_map.items():
            console.print(f"\n[bold cyan]{'─'*60}[/bold cyan]")
            console.print(f"[bold cyan]📌 {phase}[/bold cyan]")
            for action in acts:
                lbl, color = _PRIORITY_LABEL.get(action.priority, ("", "white"))
                console.print(
                    f"\n  [{color}]{lbl}[/{color}] [bold]{escape(action.title)}[/bold]"
                )
                console.print(f"  [dim]{action.category}[/dim]")
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

        # IOC summary table
        console.print()
        ioc_table = Table(title="📋 IOC Blocklist Tổng hợp", box=box.ROUNDED,
                          border_style="cyan", header_style="bold cyan")
        ioc_table.add_column("Loại IOC", style="bold")
        ioc_table.add_column("Số lượng", justify="center")
        ioc_table.add_column("Mẫu",      style="dim")
        bl = playbook.ioc_blocklist
        ioc_table.add_row("IP Addresses",  str(len(bl.get("ip_addresses",[]))),
                          ", ".join(bl.get("ip_addresses",[])[:3]))
        ioc_table.add_row("Domains",       str(len(bl.get("domains",[]))),
                          ", ".join(bl.get("domains",[])[:2]))
        ioc_table.add_row("URLs",          str(len(bl.get("urls",[]))),
                          (bl.get("urls",[""])[0][:50] if bl.get("urls") else ""))
        ioc_table.add_row("File Hashes",   str(len(bl.get("file_hashes",[]))), "")
        ioc_table.add_row("Filenames",     str(len(bl.get("filenames",[]))),
                          ", ".join(bl.get("filenames",[])[:3]))
        console.print(ioc_table)
        console.print()


# ─────────────────────────────────────────────────────────────────────────────
# File exporters
# ─────────────────────────────────────────────────────────────────────────────

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
        file   = result.file_info
        net    = result.network
        procs  = result.processes

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

        if threat.mitre_techniques:
            lines += [
                f"## 2. MITRE ATT&CK Techniques",
                f"",
                f"| ID | Tên kỹ thuật | Tactic |",
                f"|---|---|---|",
                *[f"| {t['id']} | {t['name']} | {t['tactic']} |"
                  for t in threat.mitre_techniques],
                f"",
            ]

        lines += [
            f"## 3. Hoạt Động Mạng",
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
            f"## 4. Hoạt Động Hệ Thống",
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
                *[f"| `{f['name']}` | `{f['sha256'][:16]}...` | {f['type']} |"
                  for f in procs.dropped_files[:10]],
                f"",
            ]

        lines += [
            f"## 5. Quy Trình Phản Ứng Sự Cố",
            f"",
            f"> {playbook.summary}",
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
                pri_labels = {1:"🔴 P1-CRITICAL", 2:"🟠 P2-HIGH", 3:"🟡 P3-MEDIUM", 4:"🟢 P4-LOW"}
                lines.append(f"#### {pri_labels.get(action.priority,'')} – {action.title}")
                lines.append(f"")
                lines.append(f"**Danh mục:** {action.category}")
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

        lines += [
            f"## 6. IOC Blocklist",
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

        data = {
            "generated_at": datetime.datetime.now().isoformat(),
            "task_uuid":    result.task_uuid,
            "analysis_url": result.analysis_url,
            "severity":     playbook.severity,
            "malware_name": playbook.malware_name,
            "summary":      playbook.summary,
            "ioc_blocklist": playbook.ioc_blocklist,
            "mitre_techniques": result.threat_info.mitre_techniques,
            "actions": [
                {
                    "priority":    a.priority,
                    "phase":       a.phase,
                    "category":    a.category,
                    "title":       a.title,
                    "description": a.description,
                    "commands":    a.commands,
                    "notes":       a.notes,
                }
                for a in playbook.actions
            ],
        }
        filename.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        return filename
