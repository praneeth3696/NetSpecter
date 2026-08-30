"""
NetSpecter CLI Entry Point
==========================
Real-Time Network Insecurity & Credential Leak Auditor.
"""

from __future__ import annotations
import argparse
import os
import sys
from typing import Optional

from formatter import (
    print_banner,
    print_error,
    print_info,
    print_interfaces_table,
    console
)
from sniffer import start_sniffing, analyze_pcap


def is_admin() -> bool:
    """Checks whether the process has administrator / root privileges across OSes."""
    if os.name == "nt":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    elif hasattr(os, "geteuid"):
        return os.geteuid() == 0
    return True


def check_root_privileges() -> None:
    """Verifies administrative / root privileges for live socket capture."""
    if not is_admin():
        if os.name == "nt":
            print_error("NetSpecter live sniffing requires Administrator privileges on Windows.")
            console.print("[dim]Please open PowerShell or Command Prompt as [bold white]Administrator[/bold white] and re-run:[/dim]")
            console.print("  [bold cyan]python main.py scan[/bold cyan]\n")
        else:
            print_error("NetSpecter live sniffing requires root privileges for raw socket capture.")
            console.print("[dim]Please execute with sudo: [bold white]sudo python3 main.py scan ...[/bold white][/dim]\n")
        sys.exit(1)


def list_interfaces_command() -> None:
    """Discovers and displays local host network interfaces across Windows, Linux, and macOS."""
    try:
        from scapy.all import conf
        interfaces = []

        if hasattr(conf, "ifaces") and conf.ifaces:
            for key, iface in conf.ifaces.items():
                name = getattr(iface, "name", str(key))
                ip = getattr(iface, "ip", "–") or "–"
                mac = getattr(iface, "mac", "–") or "–"
                desc = getattr(iface, "description", "")

                status = "Loopback" if "loopback" in str(desc).lower() or "lo" in name.lower() else (
                    "Active" if ip and ip != "0.0.0.0" and ip != "–" else "Standby"
                )
                desc_display = f"{status} ({desc})" if desc and desc != name else status

                interfaces.append({
                    "name": name,
                    "ip": ip,
                    "mac": mac,
                    "description": desc_display
                })
        else:
            from scapy.all import get_if_list, get_if_addr, get_if_hwaddr
            for name in get_if_list():
                try:
                    ip = get_if_addr(name)
                except Exception:
                    ip = "–"
                try:
                    mac = get_if_hwaddr(name)
                except Exception:
                    mac = "–"
                status = "Loopback" if "lo" in name else ("Active" if ip and ip != "0.0.0.0" else "Standby")
                interfaces.append({
                    "name": name,
                    "ip": ip if ip != "0.0.0.0" else "–",
                    "mac": mac if mac != "00:00:00:00:00:00" else "–",
                    "description": status
                })

        print_interfaces_table(interfaces)
    except Exception as e:
        print_error(f"Failed to enumerate network interfaces: {e}")


def run_tests_command() -> None:
    """Runs the integrated NetSpecter unit and protocol test suite."""
    from tests.test_suite import run_all_tests
    run_all_tests()


def build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netspecter",
        description="NetSpecter: Real-Time Network Plaintext Transmission & Credential Leak Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. SCAN: Live network capture
    scan_parser = subparsers.add_parser(
        "scan",
        help="Sniff readable traffic on live network interfaces for credential & token leaks"
    )
    scan_parser.add_argument(
        "--iface", "-i",
        type=str,
        default=None,
        help="Target interface (e.g. eth0, wlan0, en0). Auto-selects if omitted."
    )
    scan_parser.add_argument(
        "--bpf", "-b",
        type=str,
        default=None,
        help="Custom Berkeley Packet Filter (BPF) string."
    )
    scan_parser.add_argument(
        "--dashboard", "-d",
        action="store_true",
        help="Enable full-screen interactive cyberpunk TUI dashboard."
    )
    scan_parser.add_argument(
        "--show-secrets",
        action="store_true",
        help="Display full plaintext credentials instead of masking them."
    )
    scan_parser.add_argument(
        "--json-out",
        type=str,
        default=None,
        help="Path to export detected incidents as structured JSON."
    )
    scan_parser.add_argument(
        "--html-out",
        type=str,
        default=None,
        help="Path to generate executive HTML security audit report."
    )

    # 2. PCAP: Offline packet forensic analysis
    pcap_parser = subparsers.add_parser(
        "pcap",
        help="Analyze an offline packet capture file (.pcap or .pcapng)"
    )
    pcap_parser.add_argument(
        "file",
        type=str,
        help="Path to capture file (.pcap or .pcapng)"
    )
    pcap_parser.add_argument(
        "--show-secrets",
        action="store_true",
        help="Display full plaintext credentials instead of masking them."
    )
    pcap_parser.add_argument(
        "--json-out",
        type=str,
        default=None,
        help="Path to export detected incidents as structured JSON."
    )
    pcap_parser.add_argument(
        "--html-out",
        type=str,
        default=None,
        help="Path to generate executive HTML security audit report."
    )

    # 3. WEB: Fullstack Cyber Terminal Web UI & API
    web_parser = subparsers.add_parser(
        "web",
        help="Launch fullstack Mr. Robot Cyber-Terminal Web Dashboard (FastAPI + WebSockets)"
    )
    web_parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host IP to bind the web server (default: 127.0.0.1)"
    )
    web_parser.add_argument(
        "--port", "-p",
        type=int,
        default=8080,
        help="Port to bind the web server (default: 8080)"
    )
    web_parser.add_argument(
        "--iface", "-i",
        type=str,
        default=None,
        help="Target interface for live capture (e.g. en0, eth0, Wi-Fi)"
    )
    web_parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Do not automatically open default web browser on launch"
    )

    # 4. INTERFACES: Enumerate local interfaces
    subparsers.add_parser(
        "interfaces",
        help="List available host network interfaces with IPs and MACs"
    )

    # 5. TEST: Built-in verification test suite
    subparsers.add_parser(
        "test",
        help="Execute internal protocol and detector regression test suite"
    )

    return parser


def main() -> None:
    print_banner()
    parser = build_cli_parser()
    args = parser.parse_args()

    if args.command == "web":
        print_info("Initializing NetSpecter Cyber Terminal Web UI...")
        print_info(f"Target Binding  : [bold cyan]http://{args.host}:{args.port}[/bold cyan]")
        if args.iface:
            print_info(f"Preset Interface: [bold white]{args.iface}[/bold white]")
        print_info("Press [bold yellow]Ctrl+C[/bold yellow] in this terminal to terminate server.\n")
        from core.web.server import start_web_server
        start_web_server(
            host=args.host,
            port=args.port,
            open_browser=not args.no_browser,
            iface=args.iface
        )

    elif args.command == "scan":
        check_root_privileges()
        start_sniffing(
            iface=args.iface,
            bpf_filter=args.bpf,
            dashboard=args.dashboard,
            mask=not args.show_secrets,
            json_out=args.json_out,
            html_out=args.html_out
        )

    elif args.command == "pcap":
        if not os.path.isfile(args.file):
            print_error(f"Capture file does not exist: {args.file}")
            sys.exit(1)
        analyze_pcap(
            pcap_path=args.file,
            mask=not args.show_secrets,
            json_out=args.json_out,
            html_out=args.html_out
        )

    elif args.command == "interfaces":
        list_interfaces_command()

    elif args.command == "test":
        run_tests_command()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[dim]NetSpecter session terminated by user.[/dim]")
        sys.exit(0)
