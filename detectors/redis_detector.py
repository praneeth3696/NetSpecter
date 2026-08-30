"""
NetSpecter Redis Credential Detector
====================================
Detects unencrypted Redis AUTH commands.
"""

from __future__ import annotations
import re
from typing import Optional
from core.models import DetectionResult

_RE_REDIS_INLINE_AUTH = re.compile(r"^\s*AUTH\s+(?:([^\s\r\n]+)\s+)?([^\s\r\n]+)", re.IGNORECASE | re.MULTILINE)
_RE_REDIS_RESP_AUTH = re.compile(
    r"\*([23])\r?\n\$4\r?\nAUTH\r?\n(?:(?:\$\d+\r?\n([^\r\n]+)\r?\n)?(?:\$\d+\r?\n([^\r\n]+)))",
    re.IGNORECASE
)


class RedisDetector:
    """Detects credentials in Redis database communication over plaintext."""
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

        # Check RESP format
        resp_match = _RE_REDIS_RESP_AUTH.search(payload)
        if resp_match:
            arg_count = resp_match.group(1)
            if arg_count == "2":
                # AUTH password
                password = resp_match.group(3) or resp_match.group(2)
                username = ""
            else:
                # AUTH username password
                username = resp_match.group(2) or ""
                password = resp_match.group(3) or ""

            if password:
                return DetectionResult(
                    protocol="REDIS",
                    detection_type="redis_auth",
                    username=username,
                    password=password,
                    confidence="high",
                    severity="CRITICAL",
                    raw_snippet=resp_match.group(0).replace("\r", "\\r").replace("\n", "\\n")[:80],
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    metadata={"mode": "RESP"}
                )

        # Check inline command format: AUTH [user] password
        inline_match = _RE_REDIS_INLINE_AUTH.search(payload)
        if inline_match:
            # If group 1 exists, it's user, group 2 is pass; else group 2 is pass
            user = inline_match.group(1) or ""
            pwd = inline_match.group(2)
            # Avoid matching arbitrary text containing "AUTH"
            if pwd and len(pwd) >= 3 and not pwd.startswith("HTTP/"):
                return DetectionResult(
                    protocol="REDIS",
                    detection_type="redis_auth",
                    username=user,
                    password=pwd,
                    confidence="high",
                    severity="CRITICAL",
                    raw_snippet=inline_match.group(0).strip(),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    metadata={"mode": "inline"}
                )

        return None
