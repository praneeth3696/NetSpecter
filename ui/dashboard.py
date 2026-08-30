"""
NetSpecter Live TUI Dashboard
=============================
Interactive Cyber-Aesthetic terminal dashboard powered by Rich Live & Layout.
"""

from __future__ import annotations
import time
from typing import Sequence
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align
from core.models import DetectionResult, SessionStats, mask_secret


class LiveDashboard:
    """Renders a real-time cybersecurity telemetry dashboard in the terminal."""
    def __init__(self, interface: str, bpf_filter: str, mask: bool = True):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.mask = mask

    def make_layout(self) -> Layout:
        layout = Layout(name="root")
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="metrics", size=6),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=3),
        )
        return layout

    def render(self, stats: SessionStats, recent_detections: Sequence[DetectionResult]) -> Layout:
        layout = self.make_layout()

        # 1. Header
        header_text = Text()
        header_text.append(" ● ", style="bold green")
        header_text.append("NETSPECTER LIVE AUDIT  ", style="bold cyan")
        header_text.append(f"│ IFACE: {self.interface} ", style="bold white")
        header_text.append(f"│ FILTER: {self.bpf_filter[:35]}... ", style="dim")
        header_text.append(f"│ RUNTIME: {int(stats.elapsed_seconds)}s", style="bold yellow")
        layout["header"].update(Panel(Align.center(header_text), style="cyan", border_style="cyan"))

        # 2. Metrics Panels
        metrics_table = Table.grid(expand=True)
        metrics_table.add_column(justify="center", ratio=1)
        metrics_table.add_column(justify="center", ratio=1)
        metrics_table.add_column(justify="center", ratio=1)
        metrics_table.add_column(justify="center", ratio=1)

        p1 = Panel(
            f"[bold cyan]{stats.packets_inspected:,}[/bold cyan]\n[dim]PACKETS INSPECTED[/dim]",
            border_style="cyan"
        )
        alert_style = "bold red" if stats.alerts_count > 0 else "dim"
        p2 = Panel(
            f"[{alert_style}]{stats.alerts_count}[/{alert_style}]\n[dim]LEAKS DETECTED[/dim]",
            border_style="red" if stats.alerts_count > 0 else "dim"
        )
        p3 = Panel(
            f"[bold yellow]{stats.active_flows}[/bold yellow]\n[dim]ACTIVE FLOWS[/dim]",
            border_style="yellow"
        )
        p4 = Panel(
            f"[bold green]{stats.packets_per_second:0.1f}[/bold green]\n[dim]PACKETS / SEC[/dim]",
            border_style="green"
        )
        metrics_table.add_row(p1, p2, p3, p4)
        layout["metrics"].update(metrics_table)

        # 3. Main Event Feed Table
        event_table = Table(
            expand=True,
            border_style="dim",
            header_style="bold cyan",
            row_styles=["none", "dim"]
        )
        event_table.add_column("Time", width=8, style="dim")
        event_table.add_column("Protocol", width=10, style="bold")
        event_table.add_column("Severity", width=10)
        event_table.add_column("Source", ratio=2)
        event_table.add_column("Destination", ratio=2)
        event_table.add_column("Identity / User", ratio=2)
        event_table.add_column("Exposed Secret / Token", ratio=3)
        event_table.add_column("Confidence", width=10)

        # Show the latest up to 10 detections
        display_items = list(recent_detections)[-10:]
        if not display_items:
            event_table.add_row(
                time.strftime("%H:%M:%S"),
                "LISTENING",
                "[cyan]INFO[/cyan]",
                "–",
                "–",
                "–",
                "[dim]Awaiting unencrypted network traffic...[/dim]",
                "–"
            )
        else:
            for d in reversed(display_items):
                t_str = time.strftime("%H:%M:%S", time.localtime(d.timestamp))
                proto_styled = f"[bold cyan]{d.protocol}[/bold cyan]"
                
                sev_color = "red" if d.severity == "CRITICAL" else "yellow" if d.severity == "HIGH" else "blue"
                sev_styled = f"[{sev_color}]{d.severity}[/{sev_color}]"

                secret_display = mask_secret(d.password or d.token) if self.mask else (d.password or d.token)
                secret_styled = f"[bold red]{secret_display}[/bold red]"
                
                conf_color = "green" if d.confidence == "high" else "yellow"
                conf_styled = f"[{conf_color}]{d.confidence.upper()}[/{conf_color}]"

                src_str = f"{d.src_ip}:{d.src_port}" if d.src_port else d.src_ip
                dst_str = f"{d.dst_ip}:{d.dst_port}" if d.dst_port else d.dst_ip

                event_table.add_row(
                    t_str,
                    proto_styled,
                    sev_styled,
                    src_str,
                    dst_str,
                    d.username or "[dim]N/A[/dim]",
                    secret_styled,
                    conf_styled
                )

        layout["main"].update(Panel(event_table, title="[bold red]⚡ REAL-TIME INTERCEPTED CREDENTIAL LEAKS[/bold red]", border_style="red"))

        # 4. Footer
        footer_text = Text()
        footer_text.append("NetSpecter v2.0 ", style="bold cyan")
        footer_text.append("│ [Ctrl+C] Stop & Generate Audit Summary ", style="dim")
        footer_text.append("│ Status: Listening in Promiscuous Mode", style="green")
        layout["footer"].update(Panel(Align.center(footer_text), style="dim"))

        return layout
