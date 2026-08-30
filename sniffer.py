"""
NetSpecter Sniffer & Packet Analysis Engine
===========================================
High-performance live packet capture and offline PCAP forensic analyzer with
TCP stream reassembly and real-time aesthetic telemetry rendering.
"""

from __future__ import annotations
import sys
import time
from typing import Optional
from rich.live import Live

from formatter import (
    print_alert,
    print_error,
    print_info,
    print_success,
    print_warning,
    print_audit_summary,
    console
)
from core.models import DetectionResult, SessionStats
from core.detector_engine import DetectorEngine
from core.stream_reassembler import TCPStreamReassembler
from reporting.reporter import export_json, export_jsonl, generate_html_report
from ui.dashboard import LiveDashboard

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from scapy.all import sniff, rdpcap, TCP, IP, Raw, conf
    conf.verb = 0
except ImportError:
    print_error("Scapy module not found. Run: pip install scapy")
    sys.exit(1)

DEFAULT_BPF_FILTER = (
    "tcp port 80 or tcp port 21 or tcp port 23 or tcp port 25 or "
    "tcp port 110 or tcp port 143 or tcp port 6379 or tcp port 8080 or "
    "tcp port 8000 or tcp port 3000 or tcp port 5000"
)


class SnifferEngine:
    """Coordinates packet capture, stream reassembly, detection, and output sinks."""
    def __init__(
        self,
        mask_secrets: bool = True,
        json_out: Optional[str] = None,
        html_out: Optional[str] = None,
        use_dashboard: bool = False
    ):
        self.mask_secrets = mask_secrets
        self.json_out = json_out
        self.html_out = html_out
        self.use_dashboard = use_dashboard
        
        self.stats = SessionStats()
        self.detector = DetectorEngine()
        self.reassembler = TCPStreamReassembler()
        self.detections: list[DetectionResult] = []
        self._seen_alert_fingerprints: set[str] = set()

    def process_packet(self, pkt) -> None:
        """Processes an individual Scapy packet."""
        try:
            self.stats.record_packet()
            self.stats.active_flows = self.reassembler.active_flows_count

            if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
                return

            raw_bytes = bytes(pkt[Raw].load) if hasattr(pkt[Raw], "load") else bytes(pkt[Raw].payload)
            if not raw_bytes:
                return

            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
            seq = int(pkt[TCP].seq)

            # Reassemble TCP flow segments
            segment_bytes, stream_bytes = self.reassembler.process_segment(
                src_ip, src_port, dst_ip, dst_port, seq, raw_bytes
            )

            # First inspect segment, then reassembled stream if segment was inconclusive
            result = self.detector.inspect_payload(
                segment_bytes, src_ip, dst_ip, src_port, dst_port
            )
            if not result and len(stream_bytes) > len(segment_bytes):
                result = self.detector.inspect_payload(
                    stream_bytes, src_ip, dst_ip, src_port, dst_port
                )

            if result:
                # Deduplicate identical alerts within the stream
                fp = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}_{result.protocol}_{result.detection_type}_{result.username}_{result.password}"
                if fp in self._seen_alert_fingerprints:
                    return
                self._seen_alert_fingerprints.add(fp)

                self.detections.append(result)
                self.stats.record_detection(result)

                if not self.use_dashboard:
                    print_alert(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        detection=result,
                        mask=self.mask_secrets,
                        src_port=src_port,
                        dst_port=dst_port
                    )

        except Exception:
            # Shield sniffing loop against malformed packets
            pass

    def export_reports(self) -> None:
        """Exports JSON and HTML reports if requested."""
        if self.json_out:
            try:
                export_json(self.detections, self.json_out, mask=self.mask_secrets)
                print_success(f"Audit log exported to JSON: {self.json_out}")
            except Exception as e:
                print_error(f"Failed to export JSON report: {e}")

        if self.html_out:
            try:
                generate_html_report(self.detections, self.stats, self.html_out, mask=self.mask_secrets)
                print_success(f"Executive HTML report generated: {self.html_out}")
            except Exception as e:
                print_error(f"Failed to generate HTML report: {e}")


def resolve_interface(iface: Optional[str]):
    """Resolves human-readable interface names (e.g. 'Wi-Fi' on Windows) to Scapy network devices."""
    if not iface:
        return None
    try:
        from scapy.all import conf
        if hasattr(conf, "ifaces") and conf.ifaces:
            if iface in conf.ifaces:
                return conf.ifaces[iface]
            for k, dev in conf.ifaces.items():
                if getattr(dev, "name", "").lower() == iface.lower():
                    return dev
                if getattr(dev, "description", "").lower() == iface.lower():
                    return dev
            if iface.isdigit():
                idx = int(iface)
                for k, dev in conf.ifaces.items():
                    if getattr(dev, "index", None) == idx:
                        return dev
    except Exception:
        pass
    return iface


def start_sniffing(
    iface: Optional[str] = None,
    bpf_filter: Optional[str] = None,
    dashboard: bool = False,
    mask: bool = True,
    json_out: Optional[str] = None,
    html_out: Optional[str] = None
) -> None:
    """Starts live network packet capture across Windows, Linux, and macOS."""
    active_filter = bpf_filter if bpf_filter else DEFAULT_BPF_FILTER
    engine = SnifferEngine(
        mask_secrets=mask,
        json_out=json_out,
        html_out=html_out,
        use_dashboard=dashboard
    )

    resolved_iface = resolve_interface(iface)
    iface_name = getattr(resolved_iface, "name", str(resolved_iface)) if resolved_iface else "auto-selected"
    
    if not dashboard:
        print_info(f"Target Interface : [bold white]{iface_name}[/bold white]")
        print_info(f"Active Filter    : [dim]{active_filter}[/dim]")
        print_info(f"Secret Masking   : [bold {'green' if mask else 'yellow'}]{'ENABLED' if mask else 'DISABLED'}[/bold {'green' if mask else 'yellow'}]")
        print_info("Listening for plaintext credentials and tokens (Ctrl+C to stop)...\n")

    try:
        if dashboard:
            dash = LiveDashboard(interface=iface_name, bpf_filter=active_filter, mask=mask)
            with Live(dash.render(engine.stats, engine.detections), refresh_per_second=4, console=console) as live:
                def live_handler(pkt):
                    engine.process_packet(pkt)
                    live.update(dash.render(engine.stats, engine.detections))

                sniff(
                    iface=resolved_iface,
                    filter=active_filter,
                    prn=live_handler,
                    store=False
                )
        else:
            sniff(
                iface=resolved_iface,
                filter=active_filter,
                prn=engine.process_packet,
                store=False
            )

    except KeyboardInterrupt:
        pass
    except OSError as e:
        err_str = str(e)
        if "No such device" in err_str:
            print_error(f"Network interface not found: {iface}")
            console.print("[dim]Run [bold white]python main.py interfaces[/bold white] to view available adapters.[/dim]\n")
        elif "winpcap" in err_str.lower() or "npcap" in err_str.lower():
            print_error("Npcap packet capture driver not detected on Windows.")
            console.print("[yellow]Please download and install Npcap from: [bold white]https://npcap.com[/bold white][/yellow]")
            console.print("[dim]During installation, ensure 'Install Npcap in WinPcap API-compatible Mode' is selected.[/dim]\n")
        else:
            print_error(f"OS/Driver error initializing sniffer: {e}")
        sys.exit(1)
    except Exception as e:
        err_str = str(e)
        if "npcap" in err_str.lower() or "winpcap" in err_str.lower() or "libpcap" in err_str.lower():
            print_error("Npcap / libpcap driver error.")
            console.print("[yellow]On Windows, install Npcap from: [bold white]https://npcap.com[/bold white][/yellow]")
            console.print("[dim]Ensure 'Install Npcap in WinPcap API-compatible Mode' is enabled.[/dim]\n")
        else:
            print_error(f"Fatal error in sniffing engine: {e}")
        sys.exit(1)
    finally:
        print_audit_summary(engine.stats, engine.detections)
        engine.export_reports()


def analyze_pcap(
    pcap_path: str,
    mask: bool = True,
    json_out: Optional[str] = None,
    html_out: Optional[str] = None
) -> None:
    """Analyzes an offline PCAP/PCAPNG capture file."""
    print_info(f"Reading capture file: [bold white]{pcap_path}[/bold white]")
    engine = SnifferEngine(
        mask_secrets=mask,
        json_out=json_out,
        html_out=html_out,
        use_dashboard=False
    )

    try:
        packets = rdpcap(pcap_path)
        print_info(f"Loaded [bold cyan]{len(packets):,}[/bold cyan] packets from capture. Analyzing...")
        print()

        for pkt in packets:
            engine.process_packet(pkt)

        print_success("PCAP analysis complete.")
        print_audit_summary(engine.stats, engine.detections)
        engine.export_reports()

    except Exception as e:
        print_error(f"Failed to analyze PCAP file: {e}")
        sys.exit(1)
