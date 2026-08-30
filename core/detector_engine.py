"""
NetSpecter Central Detector Engine
==================================
Unified detection pipeline that dispatches payloads across specialized protocol
analyzers with zero-allocation byte pre-filtering and port heuristics.
"""

from __future__ import annotations
from typing import Optional
from core.models import DetectionResult
from detectors.http_credential_detector import detect_http_credentials
from detectors.ftp_detector import FTPDetector
from detectors.mail_detector import MailDetector
from detectors.redis_detector import RedisDetector
from detectors.token_detector import TokenDetector

_FAST_KEYWORDS: tuple[bytes, ...] = (
    b"user", b"pass", b"login", b"auth", b"token", b"key", b"secret",
    b"pwd", b"cookie", b"akia", b"ghp_", b"xox", b"sk_live", b"eyj",
    b"basic ", b"bearer "
)


class DetectorEngine:
    """Coordinates specialized protocol detectors and converts raw matches into DetectionResult."""
    def __init__(self):
        self.ftp_detector = FTPDetector()
        self.mail_detector = MailDetector()
        self.redis_detector = RedisDetector()
        self.token_detector = TokenDetector()

    def inspect_payload(
        self,
        payload_bytes: bytes,
        src_ip: str = "0.0.0.0",
        dst_ip: str = "0.0.0.0",
        src_port: int = 0,
        dst_port: int = 0
    ) -> Optional[DetectionResult]:
        if not payload_bytes:
            return None

        lower_bytes = payload_bytes.lower()

        # Fast byte pre-filter
        if not any(kw in lower_bytes for kw in _FAST_KEYWORDS):
            # Also allow quick checks for command signatures on specific well-known ports
            if dst_port not in (21, 23, 25, 110, 143, 6379) and src_port not in (21, 23, 25, 110, 143, 6379):
                return None

        # Decode safely
        payload_str = payload_bytes.decode("utf-8", errors="replace")

        # 1. FTP Detection (port 21 or FTP commands)
        if dst_port == 21 or src_port == 21 or payload_str.startswith(("USER ", "PASS ")):
            res = self.ftp_detector.detect(payload_str, src_ip, dst_ip, src_port, dst_port)
            if res:
                return res

        # 2. Redis Detection (port 6379 or Redis commands)
        if dst_port == 6379 or src_port == 6379 or "AUTH " in payload_str or payload_str.startswith("*"):
            res = self.redis_detector.detect(payload_str, src_ip, dst_ip, src_port, dst_port)
            if res:
                return res

        # 3. Mail Protocol Detection (SMTP, POP3, IMAP)
        if dst_port in (25, 587, 110, 143) or src_port in (25, 587, 110, 143) or "AUTH " in payload_str or "LOGIN " in payload_str:
            res = self.mail_detector.detect(payload_str, src_ip, dst_ip, src_port, dst_port)
            if res:
                return res

        # 4. Token & High-Value Secret Scanner (AWS, GitHub, Slack, Stripe, JWT)
        token_res = self.token_detector.detect(payload_str, src_ip, dst_ip, src_port, dst_port)
        if token_res:
            return token_res

        # 5. HTTP Credential Subsystem (POST forms, JSON, Query, Headers, Cookies, Multipart)
        http_raw = detect_http_credentials(payload_str)
        if http_raw:
            det_type = http_raw.get("type", "http")
            severity = "CRITICAL" if det_type in ("form", "json", "header_basic", "cookie_leak") else "HIGH"
            return DetectionResult(
                protocol="HTTP",
                detection_type=det_type,
                username=http_raw.get("username", ""),
                password=http_raw.get("password", ""),
                token=http_raw.get("password", "") if "bearer" in det_type or "token" in det_type else "",
                confidence=http_raw.get("confidence", "medium"),
                severity=severity,
                raw_snippet=http_raw.get("raw_snippet", ""),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                metadata={"source": "http_credential_detector"}
            )

        return None
