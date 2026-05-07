# -*- coding: utf-8 -*-
"""
main.py
~~~~~~~
Chương trình chính: Xây dựng quy trình phản ứng sự cố
dựa trên phân tích mã độc thực tế bằng Any.Run.

Cách sử dụng:
    python main.py                          # Chạy demo với dữ liệu mẫu Emotet
    python main.py --task <UUID>            # Phân tích task Any.Run thực
    python main.py --file <path>            # Submit file lên Any.Run để phân tích
    python main.py --url <url>              # Submit URL lên Any.Run để phân tích
    python main.py --history                # Xem lịch sử phân tích của tài khoản
    python main.py --task <UUID> --no-export # Chỉ in ra terminal, không xuất file
"""

import argparse
import os
import sys
from pathlib import Path

import io
import sys

# Fix encoding UTF-8 trên Windows
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# Đọc .env nếu có
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich import print as rprint

from anyrun_client import AnyRunClient, AnyRunAPIError, AnyRunAuthError
from analyzer import MalwareAnalyzer
from incident_response import IncidentResponseGenerator
from reporter import TerminalReporter, ReportExporter

console = Console(highlight=False)

BANNER = (
    "[bold cyan]"
    "\n   +===========================================================+"
    "\n   |      ANY.RUN MALWARE INCIDENT RESPONSE TOOL v1.0          |"
    "\n   |   Phan tich ma doc & Tu dong tao Incident Response Plan   |"
    "\n   +===========================================================+"
    "[/bold cyan]"
    "\n[dim]   Based on: NIST SP 800-61 | MITRE ATT&CK Framework[/dim]"
)


# ─────────────────────────────────────────────────────────────────────────────
# Core workflow
# ─────────────────────────────────────────────────────────────────────────────

def run_analysis_pipeline(
    report_json: dict,
    ioc_json: dict,
    output_dir: str = "reports",
    export: bool = True,
) -> None:
    """Pipeline chính: phân tích → tạo playbook → in + xuất file."""
    analyzer   = MalwareAnalyzer()
    ir_gen     = IncidentResponseGenerator()
    terminal   = TerminalReporter()
    exporter   = ReportExporter(output_dir)

    console.print("[bold green]▶ Đang phân tích dữ liệu...[/bold green]")
    result   = analyzer.parse_report(report_json, ioc_json)

    console.print("[bold green]▶ Đang tạo quy trình phản ứng sự cố...[/bold green]")
    playbook = ir_gen.generate(result)

    # In ra terminal
    terminal.print_analysis(result)
    terminal.print_playbook(playbook)

    if export:
        md_path   = exporter.export_markdown(result, playbook)
        json_path = exporter.export_json(result, playbook)
        console.print(Panel(
            f"[bold green]✅ Xuất báo cáo thành công![/bold green]\n\n"
            f"📄 Markdown: [link=file://{md_path}]{md_path}[/link]\n"
            f"📊 JSON:     [link=file://{json_path}]{json_path}[/link]",
            border_style="green",
        ))


# ─────────────────────────────────────────────────────────────────────────────
# Demo mode (không cần API key)
# ─────────────────────────────────────────────────────────────────────────────

def run_demo(output_dir: str, export: bool) -> None:
    from demo_data import DEMO_REPORT, DEMO_IOC
    console.print(Panel(
        "[bold yellow]🎭 DEMO MODE[/bold yellow]\n"
        "Đang sử dụng dữ liệu mẫu mô phỏng mã độc [bold]Emotet[/bold] "
        "(trojan/banking malware thực tế).\n"
        "Để phân tích task thực, cung cấp API key và dùng tham số --task <UUID>",
        border_style="yellow",
    ))
    run_analysis_pipeline(DEMO_REPORT, DEMO_IOC, output_dir, export)


# ─────────────────────────────────────────────────────────────────────────────
# Live API mode
# ─────────────────────────────────────────────────────────────────────────────

def run_task_analysis(client: AnyRunClient, task_uuid: str, output_dir: str, export: bool) -> None:
    console.print(f"[bold green]▶ Lấy report cho task:[/bold green] {task_uuid}")
    try:
        report_json = client.get_task_report(task_uuid)
        ioc_json    = client.get_task_iocs(task_uuid)
    except AnyRunAPIError as e:
        console.print(f"[bold red]❌ Lỗi API:[/bold red] {e}")
        sys.exit(1)
    run_analysis_pipeline(report_json, ioc_json, output_dir, export)


def run_file_submit(client: AnyRunClient, file_path: str, output_dir: str, export: bool) -> None:
    console.print(f"[bold green]▶ Đang submit file:[/bold green] {file_path}")
    try:
        result = client.submit_file(file_path)
        task_uuid = result.get("data", {}).get("taskid", "")
        if not task_uuid:
            console.print(f"[red]Không nhận được task UUID từ API. Response: {result}[/red]")
            sys.exit(1)
        console.print(f"[bold green]✅ Đã submit thành công![/bold green] Task UUID: [cyan]{task_uuid}[/cyan]")
        console.print("[yellow]⏳ Đang chờ phân tích hoàn tất (có thể mất 1-3 phút)...[/yellow]")
        report_json = client.wait_for_task(task_uuid)
        ioc_json    = client.get_task_iocs(task_uuid)
    except (AnyRunAPIError, TimeoutError, FileNotFoundError) as e:
        console.print(f"[bold red]❌ Lỗi:[/bold red] {e}")
        sys.exit(1)
    run_analysis_pipeline(report_json, ioc_json, output_dir, export)


def run_url_submit(client: AnyRunClient, url: str, output_dir: str, export: bool) -> None:
    console.print(f"[bold green]▶ Đang submit URL:[/bold green] {url}")
    try:
        result = client.submit_url(url)
        task_uuid = result.get("data", {}).get("taskid", "")
        if not task_uuid:
            console.print(f"[red]Không nhận được task UUID. Response: {result}[/red]")
            sys.exit(1)
        console.print(f"[bold green]✅ Đã submit thành công![/bold green] Task UUID: [cyan]{task_uuid}[/cyan]")
        console.print("[yellow]⏳ Đang chờ phân tích hoàn tất...[/yellow]")
        report_json = client.wait_for_task(task_uuid)
        ioc_json    = client.get_task_iocs(task_uuid)
    except (AnyRunAPIError, TimeoutError) as e:
        console.print(f"[bold red]❌ Lỗi:[/bold red] {e}")
        sys.exit(1)
    run_analysis_pipeline(report_json, ioc_json, output_dir, export)


def run_history(client: AnyRunClient) -> None:
    console.print("[bold green]▶ Lấy lịch sử phân tích...[/bold green]")
    try:
        history = client.get_history(limit=10)
        tasks = history.get("data", {}).get("tasks", []) or []
    except AnyRunAPIError as e:
        console.print(f"[bold red]❌ Lỗi API:[/bold red] {e}")
        sys.exit(1)

    if not tasks:
        console.print("[yellow]Không có task nào trong lịch sử.[/yellow]")
        return

    from rich.table import Table
    from rich import box
    table = Table(title="📋 Lịch sử phân tích Any.Run", box=box.ROUNDED, border_style="cyan")
    table.add_column("UUID",        style="cyan", no_wrap=True)
    table.add_column("Tên file",    style="white")
    table.add_column("Verdict",     style="bold")
    table.add_column("Ngày tạo",    style="dim")

    for task in tasks:
        uuid    = task.get("uuid", "")
        name    = task.get("name", "N/A")
        verdict = task.get("verdict", {})
        threat  = verdict.get("threatLevelText", "unknown")
        created = task.get("date", "")[:10] if task.get("date") else ""
        color = "red" if "malicious" in threat.lower() else "yellow" if "suspicious" in threat.lower() else "green"
        table.add_row(uuid, name, f"[{color}]{threat}[/{color}]", created)

    console.print(table)


# ─────────────────────────────────────────────────────────────────────────────
# Interactive menu (khi không có tham số)
# ─────────────────────────────────────────────────────────────────────────────

def interactive_menu(api_key: str, output_dir: str) -> None:
    console.print(Panel(
        "[bold]Chọn chế độ hoạt động:[/bold]\n\n"
        "  [cyan]1.[/cyan] Demo (Emotet - không cần API key)\n"
        "  [cyan]2.[/cyan] Phân tích task Any.Run có sẵn (cần UUID)\n"
        "  [cyan]3.[/cyan] Submit file mới lên Any.Run\n"
        "  [cyan]4.[/cyan] Submit URL mới lên Any.Run\n"
        "  [cyan]5.[/cyan] Xem lịch sử phân tích\n"
        "  [cyan]q.[/cyan] Thoát",
        title="🛡️  Any.Run IR Tool",
        border_style="cyan",
    ))

    choice = Prompt.ask("Lựa chọn", choices=["1","2","3","4","5","q"], default="1")

    if choice == "q":
        console.print("[dim]Tạm biệt![/dim]")
        return

    if choice == "1":
        run_demo(output_dir, export=True)
        return

    # Cần API key cho các tùy chọn còn lại
    if not api_key:
        api_key = Prompt.ask("[bold yellow]Nhập API key Any.Run của bạn[/bold yellow]", password=True)

    try:
        client = AnyRunClient(api_key)
    except AnyRunAuthError as e:
        console.print(f"[red]{e}[/red]")
        return

    if choice == "2":
        uuid = Prompt.ask("Nhập Task UUID")
        run_task_analysis(client, uuid.strip(), output_dir, export=True)
    elif choice == "3":
        path = Prompt.ask("Nhập đường dẫn file")
        run_file_submit(client, path.strip(), output_dir, export=True)
    elif choice == "4":
        url = Prompt.ask("Nhập URL cần phân tích")
        run_url_submit(client, url.strip(), output_dir, export=True)
    elif choice == "5":
        run_history(client)


# ─────────────────────────────────────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="anyrun-ir",
        description="Phân tích mã độc với Any.Run và tạo Incident Response Playbook",
    )
    group = p.add_mutually_exclusive_group()
    group.add_argument("--demo",    action="store_true",
                       help="Chạy demo với dữ liệu mẫu Emotet (không cần API key)")
    group.add_argument("--task",    metavar="UUID",
                       help="Phân tích task Any.Run theo UUID")
    group.add_argument("--file",    metavar="PATH",
                       help="Submit file lên Any.Run để phân tích")
    group.add_argument("--url",     metavar="URL",
                       help="Submit URL lên Any.Run để phân tích")
    group.add_argument("--history", action="store_true",
                       help="Xem lịch sử phân tích của tài khoản")

    p.add_argument("--api-key",   metavar="KEY",
                   help="API key Any.Run (hoặc đặt biến môi trường ANYRUN_API_KEY)")
    p.add_argument("--output",    metavar="DIR", default="reports",
                   help="Thư mục lưu báo cáo (mặc định: ./reports)")
    p.add_argument("--no-export", action="store_true",
                   help="Không xuất file báo cáo, chỉ in ra terminal")
    return p


def main() -> None:
    console.print(BANNER)
    parser = build_parser()
    args   = parser.parse_args()

    api_key = args.api_key or os.getenv("ANYRUN_API_KEY", "")
    export  = not args.no_export

    # Không có tham số → interactive menu
    if not any([args.demo, args.task, args.file, args.url, args.history]):
        interactive_menu(api_key, args.output)
        return

    if args.demo:
        run_demo(args.output, export)
        return

    # Các lệnh cần client
    if not api_key:
        console.print(
            "[bold red]❌ Cần API key![/bold red]\n"
            "Cung cấp bằng --api-key hoặc đặt biến môi trường ANYRUN_API_KEY.\n"
            "Lấy API key tại: https://app.any.run/ → Profile → API and Limits"
        )
        sys.exit(1)

    try:
        client = AnyRunClient(api_key)
    except AnyRunAuthError as e:
        console.print(f"[bold red]❌ {e}[/bold red]")
        sys.exit(1)

    if args.task:
        run_task_analysis(client, args.task, args.output, export)
    elif args.file:
        run_file_submit(client, args.file, args.output, export)
    elif args.url:
        run_url_submit(client, args.url, args.output, export)
    elif args.history:
        run_history(client)


if __name__ == "__main__":
    main()
