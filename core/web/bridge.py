"""
NetSpecter Web Bridge & Telemetry Dispatcher
============================================
Thread-safe bridge connecting Scapy packet ingestion and stream reassembly
to asynchronous FastAPI WebSocket clients with live simulation capabilities.
"""

from __future__ import annotations
import asyncio
import base64
import json
import logging
import threading
import time
from typing import Any, Optional, Set
from fastapi import WebSocket

from core.models import DetectionResult, SessionStats, FlowKey, mask_secret
from core.detector_engine import DetectorEngine
from core.stream_reassembler import TCPStreamReassembler

logger = logging.getLogger("netspecter.bridge")

try:
    from scapy.all import sniff, TCP, IP, Raw, conf
    conf.verb = 0
except ImportError:
    sniff = None


def generate_hex_dump(data: bytes, max_len: int = 256) -> str:
    """Formats bytes into a standard 16-byte offset hex + ASCII dump."""
    if not data:
        return ""
    data = data[:max_len]
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_bytes = " ".join(f"{b:02x}" for b in chunk)
        # Pad hex display if chunk is smaller than 16
        hex_padded = f"{hex_bytes:<48}"
        ascii_repr = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{i:04x}  {hex_padded}  |{ascii_repr}|")
    return "\n".join(lines)


class WebSnifferBridge:
    """Manages live sniffing state, WebSocket connections, and real-time event broadcasting."""
    def __init__(self):
        self.is_capturing: bool = False
        self.active_iface: Optional[str] = None
        self.bpf_filter: str = (
            "tcp port 80 or tcp port 21 or tcp port 23 or tcp port 25 or "
            "tcp port 110 or tcp port 143 or tcp port 6379 or tcp port 8080 or "
            "tcp port 8000 or tcp port 3000 or tcp port 5000"
        )
        self.stats = SessionStats()
        self.detector = DetectorEngine()
        self.reassembler = TCPStreamReassembler()
        self.detections: list[DetectionResult] = []
        self._seen_alert_fps: set[str] = set()

        self._active_sockets: Set[WebSocket] = set()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._sniff_thread: Optional[threading.Thread] = None
        self._stop_sniff_event = threading.Event()

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    async def connect_socket(self, ws: WebSocket) -> None:
        await ws.accept()
        self._active_sockets.add(ws)
        # Send initial sync payload
        init_payload = {
            "type": "init",
            "is_capturing": self.is_capturing,
            "active_iface": self.active_iface or "auto",
            "bpf_filter": self.bpf_filter,
            "stats": self.get_stats_dict(),
            "detections": [self._format_detection_for_web(d) for d in self.detections[-50:]],
            "flows": self.get_active_flows_list()
        }
        await ws.send_json(init_payload)

    def disconnect_socket(self, ws: WebSocket) -> None:
        self._active_sockets.discard(ws)

    def broadcast_sync(self, message: dict[str, Any]) -> None:
        """Thread-safe dispatch to all connected WebSockets."""
        if not self._loop or not self._active_sockets:
            return
        asyncio.run_coroutine_threadsafe(self.broadcast(message), self._loop)

    async def broadcast(self, message: dict[str, Any]) -> None:
        dead_sockets = set()
        for ws in self._active_sockets:
            try:
                await ws.send_json(message)
            except Exception:
                dead_sockets.add(ws)
        for dead in dead_sockets:
            self._active_sockets.discard(dead)

    def process_packet(self, pkt) -> None:
        """Callback invoked by Scapy in background capture thread."""
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

            # Reassemble TCP segments
            segment_bytes, stream_bytes = self.reassembler.process_segment(
                src_ip, src_port, dst_ip, dst_port, seq, raw_bytes
            )

            result = self.detector.inspect_payload(
                segment_bytes, src_ip, dst_ip, src_port, dst_port
            )
            if not result and len(stream_bytes) > len(segment_bytes):
                result = self.detector.inspect_payload(
                    stream_bytes, src_ip, dst_ip, src_port, dst_port
                )

            # Broadcast packet telemetry beat
            self.broadcast_sync({
                "type": "packet_beat",
                "stats": self.get_stats_dict(),
                "flows_count": self.reassembler.active_flows_count,
            })

            if result:
                fp = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}_{result.protocol}_{result.detection_type}_{result.username}_{result.password}"
                if fp in self._seen_alert_fps:
                    return
                self._seen_alert_fps.add(fp)

                self.detections.append(result)
                self.stats.record_detection(result)

                # Broadcast live incident event
                formatted = self._format_detection_for_web(result, raw_bytes=raw_bytes)
                self.broadcast_sync({
                    "type": "leak_detected",
                    "leak": formatted,
                    "stats": self.get_stats_dict()
                })

        except Exception as e:
            logger.debug(f"Packet handling error: {e}")

    def start_capture(self, iface: Optional[str] = None, bpf: Optional[str] = None) -> bool:
        if self.is_capturing:
            return True

        if bpf:
            self.bpf_filter = bpf
        self.active_iface = iface
        self._stop_sniff_event.clear()
        self.is_capturing = True

        def _worker():
            try:
                from sniffer import resolve_interface
                resolved = resolve_interface(self.active_iface)
                
                sniff(
                    iface=resolved,
                    filter=self.bpf_filter,
                    prn=self.process_packet,
                    store=False,
                    stop_filter=lambda p: self._stop_sniff_event.is_set()
                )
            except Exception as e:
                logger.error(f"Live sniffing error: {e}")
            finally:
                self.is_capturing = False
                self.broadcast_sync({
                    "type": "capture_status",
                    "is_capturing": False,
                    "stats": self.get_stats_dict()
                })

        self._sniff_thread = threading.Thread(target=_worker, daemon=True)
        self._sniff_thread.start()

        self.broadcast_sync({
            "type": "capture_status",
            "is_capturing": True,
            "iface": self.active_iface or "auto",
            "filter": self.bpf_filter,
            "stats": self.get_stats_dict()
        })
        return True

    def stop_capture(self) -> None:
        if not self.is_capturing:
            return
        self._stop_sniff_event.set()
        self.is_capturing = False
        self.broadcast_sync({
            "type": "capture_status",
            "is_capturing": False,
            "stats": self.get_stats_dict()
        })

    def simulate_leak(self, scenario: str) -> dict[str, Any]:
        """Generates mock unencrypted packet traffic for instant web UI testing."""
        scenario = scenario.lower()
        now = time.time()
        
        if scenario == "http":
            src_ip, dst_ip = "192.168.1.105", "198.51.100.2"
            src_port, dst_port = 52140, 80
            payload = (
                b"POST /api/v1/login HTTP/1.1\r\n"
                b"Host: auth.internal.corp\r\n"
                b"Content-Type: application/x-www-form-urlencoded\r\n"
                b"Content-Length: 47\r\n\r\n"
                b"username=secops_admin&password=CyberSecretP@ss2026!"
            )
        elif scenario == "ftp":
            src_ip, dst_ip = "192.168.1.112", "198.51.100.21"
            src_port, dst_port = 49200, 21
            self.detector.ftp_detector.detect("USER backup_operator\r\n", src_ip=src_ip)
            payload = b"PASS ProductionVaultP@ssw0rd!\r\n"
        elif scenario == "redis":
            src_ip, dst_ip = "10.0.0.40", "10.0.0.200"
            src_port, dst_port = 61200, 6379
            payload = b"*2\r\n$4\r\nAUTH\r\n$18\r\nRedisClusterKey99!\r\n"
        elif scenario == "cookie":
            src_ip, dst_ip = "192.168.1.150", "198.51.100.5"
            src_port, dst_port = 53400, 8080
            payload = (
                b"GET /dashboard HTTP/1.1\r\n"
                b"Host: intranet.corp\r\n"
                b"Cookie: sessionid=e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9; role=admin\r\n\r\n"
            )
        elif scenario == "aws":
            src_ip, dst_ip = "10.0.1.20", "198.51.100.99"
            src_port, dst_port = 54800, 80
            payload = (
                b"GET /deploy?aws_key=AKIAIOSFODNN7EXAMPLE&region=us-east-1 HTTP/1.1\r\n"
                b"Host: ci-cd.internal.corp\r\n\r\n"
            )
        elif scenario == "jwt":
            src_ip, dst_ip = "10.0.2.85", "198.51.100.75"
            src_port, dst_port = 56200, 8000
            h = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
            p = base64.urlsafe_b64encode(b'{"sub":"usr_9876","email":"fsociety@protonmail.ch","role":"root"}').decode().rstrip("=")
            jwt_token = f"{h}.{p}.insecureSignature123456"
            payload = f"GET /admin HTTP/1.1\r\nAuthorization: Bearer {jwt_token}\r\n\r\n".encode("utf-8")
        else:
            # Default generic form
            src_ip, dst_ip = "192.168.1.200", "198.51.100.2"
            src_port, dst_port = 50000, 80
            payload = b"POST /login HTTP/1.1\r\n\r\nusername=testuser&password=SecretPass123!"

        # Process through detector pipeline
        self.stats.record_packet()
        result = self.detector.inspect_payload(payload, src_ip, dst_ip, src_port, dst_port)
        if result:
            self.detections.append(result)
            self.stats.record_detection(result)
            formatted = self._format_detection_for_web(result, raw_bytes=payload)
            self.broadcast_sync({
                "type": "leak_detected",
                "leak": formatted,
                "stats": self.get_stats_dict()
            })
            return formatted

        return {"status": "inconclusive"}

    def _format_detection_for_web(self, d: DetectionResult, raw_bytes: Optional[bytes] = None) -> dict[str, Any]:
        """Enriches DetectionResult with hex dump, masked secrets, and web UI badges."""
        if raw_bytes is None:
            raw_bytes = d.raw_snippet.encode("utf-8", errors="replace") if d.raw_snippet else b""

        return {
            "id": f"det_{int(d.timestamp * 1000)}_{abs(hash(d.password or d.token)) % 10000}",
            "timestamp": d.timestamp,
            "time_str": time.strftime("%H:%M:%S", time.localtime(d.timestamp)),
            "protocol": d.protocol,
            "type": d.detection_type,
            "severity": d.severity,
            "confidence": d.confidence,
            "src_ip": d.src_ip,
            "dst_ip": d.dst_ip,
            "src_port": d.src_port,
            "dst_port": d.dst_port,
            "src": f"{d.src_ip}:{d.src_port}" if d.src_port else d.src_ip,
            "dst": f"{d.dst_ip}:{d.dst_port}" if d.dst_port else d.dst_ip,
            "username": d.username,
            "password": d.password,
            "token": d.token,
            "masked_secret": mask_secret(d.password or d.token),
            "raw_snippet": d.raw_snippet,
            "hex_dump": generate_hex_dump(raw_bytes),
            "metadata": d.metadata
        }

    def get_stats_dict(self) -> dict[str, Any]:
        return {
            "packets_inspected": self.stats.packets_inspected,
            "alerts_count": self.stats.alerts_count,
            "active_flows": self.reassembler.active_flows_count,
            "elapsed_seconds": int(self.stats.elapsed_seconds),
            "packets_per_sec": round(self.stats.packets_per_second, 1),
            "protocols": self.stats.protocol_counts,
            "top_sources": self.stats.top_sources,
            "top_destinations": self.stats.top_destinations,
            "severities": {
                "critical": sum(1 for d in self.detections if d.severity == "CRITICAL"),
                "high": sum(1 for d in self.detections if d.severity == "HIGH"),
                "medium": sum(1 for d in self.detections if d.severity == "MEDIUM"),
            }
        }

    def get_active_flows_list(self) -> list[dict[str, Any]]:
        flows = []
        for k, v in list(self.reassembler.flows.items())[:25]:
            flows.append({
                "src": f"{k.src_ip}:{k.src_port}",
                "dst": f"{k.dst_ip}:{k.dst_port}",
                "proto": k.protocol,
                "buffered_bytes": len(v.buffer),
                "last_active": int(time.time() - v.last_seen)
            })
        return flows


# Global singleton bridge instance
bridge = WebSnifferBridge()
