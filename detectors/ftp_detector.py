"""
NetSpecter FTP Credential Detector
==================================
Detects cleartext FTP USER / PASS command credentials.
"""

from __future__ import annotations
import re
from typing import Optional
from core.models import DetectionResult

_RE_FTP_USER = re.compile(r"^\s*USER\s+([^\r\n]+)", re.IGNORECASE | re.MULTILINE)
_RE_FTP_PASS = re.compile(r"^\s*PASS\s+([^\r\n]+)", re.IGNORECASE | re.MULTILINE)


class FTPDetector:
    """Detects credentials in cleartext File Transfer Protocol (FTP) streams."""
    def __init__(self):
        # Keeps short memory of last seen user per client IP to pair with PASS
        self._user_cache: dict[str, str] = {}

    def detect(
        self,
        payload: str,
        src_ip: str = "0.0.0.0",
        dst_ip: str = "0.0.0.0",
        src_port: int = 0,
        dst_port: int = 0
    ) -> Optional[DetectionResult]:
        if not payload:
            return None

        # Check for USER command
        user_match = _RE_FTP_USER.search(payload)
        if user_match:
            user = user_match.group(1).strip()
            self._user_cache[src_ip] = user

        # Check for PASS command
        pass_match = _RE_FTP_PASS.search(payload)
        if pass_match:
            password = pass_match.group(1).strip()
            username = self._user_cache.get(src_ip, "")
            
            snippet = payload[max(0, pass_match.start() - 20): min(len(payload), pass_match.end() + 20)]
            
            return DetectionResult(
                protocol="FTP",
                detection_type="ftp_credentials",
                username=username,
                password=password,
                confidence="high" if username else "medium",
                severity="CRITICAL",
                raw_snippet=snippet.strip(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                metadata={"command": "PASS"}
            )

        return None
