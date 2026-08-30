"""
NetSpecter Visual Formatter & Terminal Themes
=============================================
Cyber-aesthetic CLI styling, glowing banners, incident alert panels, and summary tables.
"""

from __future__ import annotations
from typing import Any, Sequence
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align
from core.models import DetectionResult, SessionStats, mask_secret

console = Console()

BANNER_ART = r"""
 ███╗   ██╗███████╗████████╗███████╗██████╗ ███████╗ ██████╗████████╗███████╗██████╗ 
 ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
 ██╔██╗ ██║█████╗     ██║   ███████╗██████╔╝█████╗  ██║        ██║   █████╗  ██████╔╝
 ██║╚██╗██║██╔══╝     ██║   ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══╝  ██╔══██╗
 ██║ ╚████║███████╗   ██║   ███████║██║     ███████╗╚██████╗   ██║   ███████╗██║  ██║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
"""


def print_banner() -> None:
    """Renders the NetSpecter cyber-aesthetic ASCII art banner."""
    console.print(f"[bold cyan]{BANNER_ART}[/bold cyan]")
    
    subtext = Text()
    subtext.append("Real-Time Network Insecurity & Credential Leak Auditor ", style="bold white")
    subtext.append("│ v2.0 Modular IDS ", style="bold magenta")
    subtext.append("│ Scapy Engine", style="dim")
    
    console.print(Align.center(subtext))
    console.print()


def print_alert(
    src_ip: str,
    dst_ip: str,
    detection: Any,
    mask: bool = True,
    src_port: int = 0,
    dst_port: int = 0
) -> None:
    """
    Renders a high-visibility, glowing red incident alert card in the terminal.
    Compatible with both DetectionResult instances and legacy detection dicts.
    """
    if isinstance(detection, DetectionResult):
        proto = detection.protocol
        det_type = detection.detection_type
        user = detection.username
        secret = detection.password or detection.token
        conf = detection.confidence
        sev = detection.severity
        snippet = detection.raw_snippet
        src_port = detection.src_port or src_port
        dst_port = detection.dst_port or dst_port
    else:
        proto = "HTTP"
        det_type = detection.get("type", "Unknown")
        user = detection.get("username", "")
        secret = detection.get("password", "")
        conf = detection.get("confidence", "low")
        sev = "CRITICAL" if det_type in ("form", "json", "header_basic") else "HIGH"
        snippet = detection.get("raw_snippet", "")

    src_endpoint = f"{src_ip}:{src_port}" if src_port else src_ip
    dst_endpoint = f"{dst_ip}:{dst_port}" if dst_port else dst_ip
    secret_display = mask_secret(secret) if mask else secret

    # Build structured alert layout
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right", width=18)
    grid.add_column(style="bold white")

    grid.add_row("Protocol:", f"[bold cyan]{proto.upper()}[/bold cyan] [dim]({det_type})[/dim]")
    grid.add_row("Severity:", f"[bold red on black] {sev.upper()} [/bold red on black]")
    grid.add_row("Source Host:", f"[bold white]{src_endpoint}[/bold white]")
    grid.add_row("Target Host:", f"[bold white]{dst_endpoint}[/bold white]")

    if user:
        grid.add_row("Username / ID:", f"[bold green]{user}[/bold green]")
    if secret:
        grid.add_row("Exposed Secret:", f"[bold red on black]{secret_display}[/bold red on black]")

    conf_style = "green" if conf.lower() == "high" else "yellow"
    grid.add_row("Confidence:", f"[{conf_style}]{conf.upper()}[/{conf_style}]")

    if snippet:
        clean_snippet = snippet.replace("\r", " ").replace("\n", " ").strip()
        grid.add_row("Raw Payload:", f"[dim italic]{clean_snippet[:100]}[/dim italic]")

    panel = Panel(
        grid,
        title="[bold red]⚠️  INSECURE CREDENTIAL TRANSMISSION DETECTED  ⚠️[/bold red]",
        subtitle="[dim red]Plaintext transmission vulnerable to passive wiretapping & MITM[/dim red]",
        border_style="red",
        padding=(1, 2)
    )
    console.print(panel)
    console.print()


def print_audit_summary(stats: SessionStats, detections: Sequence[DetectionResult]) -> None:
    """Renders a concluding audit summary report in the console."""
    console.print()
    console.print("[bold cyan]════════════════════════════════════════════════════════════════════════════════[/bold cyan]")
    console.print(Align.center("[bold white]NETSPECTER AUDIT SESSION REPORT[/bold white]"))
    console.print("[bold cyan]════════════════════════════════════════════════════════════════════════════════[/bold cyan]")
    console.print()

    # Overview Metrics Table
    meta_table = Table(show_header=False, box=None)
    meta_table.add_column(style="cyan", width=26)
    meta_table.add_column(style="bold white")

    meta_table.add_row("Total Packets Inspected:", f"{stats.packets_inspected:,}")
    meta_table.add_row("Session Elapsed Time:", f"{stats.elapsed_seconds:0.1f}s")
    meta_table.add_row("Average Throughput:", f"{stats.packets_per_second:0.1f} packets/sec")
    meta_table.add_row("Total Insecure Leaks:", f"[bold red]{stats.alerts_count}[/bold red]")

    console.print(Panel(meta_table, title="Session Overview", border_style="cyan"))

    if detections:
        findings_table = Table(title="[bold red]Flagged Plaintext Transmissions[/bold red]", border_style="dim")
        findings_table.add_column("#", style="dim", width=4)
        findings_table.add_column("Protocol", style="bold cyan")
        findings_table.add_column("Source", style="white")
        findings_table.add_column("Destination", style="white")
        findings_table.add_column("Identity", style="green")
        findings_table.add_column("Exposed Secret (Masked)", style="bold red")
        findings_table.add_column("Severity", style="bold")

        for idx, d in enumerate(detections, 1):
            src = f"{d.src_ip}:{d.src_port}" if d.src_port else d.src_ip
            dst = f"{d.dst_ip}:{d.dst_port}" if d.dst_port else d.dst_ip
            sev_color = "red" if d.severity == "CRITICAL" else "yellow"
            findings_table.add_row(
                str(idx),
                d.protocol,
                src,
                dst,
                d.username or "–",
                mask_secret(d.password or d.token),
                f"[{sev_color}]{d.severity}[/{sev_color}]"
            )
        console.print(findings_table)
    else:
        console.print("[bold green]✔ No plaintext credential leaks detected during this session.[/bold green]")

    console.print()


def print_interfaces_table(interfaces: Sequence[dict[str, Any]]) -> None:
    """Renders a styled table of discovered host network interfaces."""
    table = Table(title="[bold cyan]Discovered Host Network Interfaces[/bold cyan]", border_style="cyan")
    table.add_column("Interface Name", style="bold white", width=16)
    table.add_column("IPv4 Address", style="green", width=18)
    table.add_column("MAC Address", style="dim", width=20)
    table.add_column("Status / Description", style="cyan")

    for iface in interfaces:
        table.add_row(
            iface.get("name", ""),
            iface.get("ip", "–"),
            iface.get("mac", "–"),
            iface.get("description", "Active")
        )
    console.print(table)


def print_error(msg: str) -> None:
    console.print(f"[bold red][✖] {msg}[/bold red]")


def print_info(msg: str) -> None:
    console.print(f"[bold cyan][ℹ] {msg}[/bold cyan]")


def print_success(msg: str) -> None:
    console.print(f"[bold green][✔] {msg}[/bold green]")


def print_warning(msg: str) -> None:
    console.print(f"[bold yellow][⚠] {msg}[/bold yellow]")
