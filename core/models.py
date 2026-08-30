"""
NetSpecter Data Models
======================
Core data schemas for detections, flows, and session telemetry.
"""

from __future__ import annotations
import time
from dataclasses import dataclass, field
from typing import Any, Optional


def mask_secret(secret: str, visible_start: int = 1, visible_end: int = 1) -> str:
    """Mask a secret string for safe display while retaining minimal length context."""
    if not secret:
        return ""
    length = len(secret)
    if length <= 3:
        return "*" * length
    if length <= 6:
        return secret[0] + ("*" * (length - 1))
    
    start_chars = min(visible_start, 2)
    end_chars = min(visible_end, 2)
    masked_count = length - start_chars - end_chars
    return secret[:start_chars] + ("*" * masked_count) + secret[-end_chars:]


@dataclass
class DetectionResult:
    """Represents a discovered plaintext credential, token, or insecure session leak."""
    protocol: str                          # HTTP, FTP, SMTP, POP3, IMAP, REDIS, TELNET, etc.
    detection_type: str                    # form, json, query, header_basic, ftp_login, etc.
    username: str = ""
    password: str = ""
    token: str = ""
    confidence: str = "medium"             # high, medium, low
    severity: str = "HIGH"                 # CRITICAL, HIGH, MEDIUM, LOW
    raw_snippet: str = ""
    src_ip: str = "0.0.0.0"
    dst_ip: str = "0.0.0.0"
    src_port: int = 0
    dst_port: int = 0
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self, mask: bool = False) -> dict[str, Any]:
        pwd = mask_secret(self.password) if mask else self.password
        tok = mask_secret(self.token) if mask else self.token
        return {
            "timestamp": self.timestamp,
            "protocol": self.protocol,
            "type": self.detection_type,
            "src": f"{self.src_ip}:{self.src_port}" if self.src_port else self.src_ip,
            "dst": f"{self.dst_ip}:{self.dst_port}" if self.dst_port else self.dst_ip,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "username": self.username,
            "password": pwd,
            "token": tok,
            "confidence": self.confidence,
            "severity": self.severity,
            "raw_snippet": self.raw_snippet,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class FlowKey:
    """Unique 5-tuple identifier for a directional TCP stream."""
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str = "TCP"

    @property
    def reverse(self) -> FlowKey:
        return FlowKey(
            src_ip=self.dst_ip,
            src_port=self.dst_port,
            dst_ip=self.src_ip,
            dst_port=self.src_port,
            protocol=self.protocol
        )


@dataclass
class SessionStats:
    """Tracks global capture metrics for terminal and report outputs."""
    start_time: float = field(default_factory=time.time)
    packets_inspected: int = 0
    packets_matched: int = 0
    alerts_count: int = 0
    active_flows: int = 0
    protocol_counts: dict[str, int] = field(default_factory=dict)
    detection_type_counts: dict[str, int] = field(default_factory=dict)
    top_sources: dict[str, int] = field(default_factory=dict)
    top_destinations: dict[str, int] = field(default_factory=dict)

    def record_packet(self) -> None:
        self.packets_inspected += 1

    def record_detection(self, detection: DetectionResult) -> None:
        self.alerts_count += 1
        self.protocol_counts[detection.protocol] = self.protocol_counts.get(detection.protocol, 0) + 1
        self.detection_type_counts[detection.detection_type] = (
            self.detection_type_counts.get(detection.detection_type, 0) + 1
        )
        self.top_sources[detection.src_ip] = self.top_sources.get(detection.src_ip, 0) + 1
        self.top_destinations[detection.dst_ip] = self.top_destinations.get(detection.dst_ip, 0) + 1

    @property
    def elapsed_seconds(self) -> float:
        return max(0.1, time.time() - self.start_time)

    @property
    def packets_per_second(self) -> float:
        return self.packets_inspected / self.elapsed_seconds
