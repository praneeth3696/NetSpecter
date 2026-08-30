"""
NetSpecter Email Protocol Credential Detector
=============================================
Detects plaintext credentials transmitted over SMTP, POP3, and IMAP.
"""

from __future__ import annotations
import base64
import binascii
import re
from typing import Optional
from core.models import DetectionResult

# SMTP patterns
_RE_SMTP_AUTH_PLAIN = re.compile(r"^\s*AUTH\s+PLAIN\s+([A-Za-z0-9+/=]{8,})", re.IGNORECASE | re.MULTILINE)
_RE_SMTP_AUTH_LOGIN = re.compile(r"^\s*AUTH\s+LOGIN\b", re.IGNORECASE | re.MULTILINE)

# POP3 patterns
_RE_POP3_USER = re.compile(r"^\s*USER\s+([^\r\n]+)", re.IGNORECASE | re.MULTILINE)
_RE_POP3_PASS = re.compile(r"^\s*PASS\s+([^\r\n]+)", re.IGNORECASE | re.MULTILINE)

# IMAP patterns
_RE_IMAP_LOGIN = re.compile(r"^\s*\S+\s+LOGIN\s+([^\r\n\s]+)\s+([^\r\n\s]+)", re.IGNORECASE | re.MULTILINE)


class MailDetector:
    """Detects credentials in SMTP, POP3, and IMAP cleartext communications."""
    def __init__(self):
        self._smtp_state: dict[str, dict[str, str]] = {}
        self._pop3_user: dict[str, str] = {}

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

        # 1. IMAP LOGIN command
        imap_match = _RE_IMAP_LOGIN.search(payload)
        if imap_match:
            user = imap_match.group(1).strip('"\'')
            pwd = imap_match.group(2).strip('"\'')
            return DetectionResult(
                protocol="IMAP",
                detection_type="imap_login",
                username=user,
                password=pwd,
                confidence="high",
                severity="CRITICAL",
                raw_snippet=imap_match.group(0).strip(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                metadata={"port": dst_port or 143}
            )

        # 2. POP3 USER / PASS
        pop_user = _RE_POP3_USER.search(payload)
        if pop_user:
            self._pop3_user[src_ip] = pop_user.group(1).strip()

        pop_pass = _RE_POP3_PASS.search(payload)
        if pop_pass:
            user = self._pop3_user.get(src_ip, "")
            pwd = pop_pass.group(1).strip()
            return DetectionResult(
                protocol="POP3",
                detection_type="pop3_credentials",
                username=user,
                password=pwd,
                confidence="high" if user else "medium",
                severity="CRITICAL",
                raw_snippet=pop_pass.group(0).strip(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                metadata={"port": dst_port or 110}
            )

        # 3. SMTP AUTH PLAIN: format is base64(\0authzid\0authcid\0passwd)
        smtp_plain = _RE_SMTP_AUTH_PLAIN.search(payload)
        if smtp_plain:
            b64_val = smtp_plain.group(1)
            try:
                decoded = base64.b64decode(b64_val)
                parts = decoded.split(b"\x00")
                if len(parts) >= 3:
                    user = parts[1].decode("utf-8", errors="replace")
                    pwd = parts[2].decode("utf-8", errors="replace")
                    return DetectionResult(
                        protocol="SMTP",
                        detection_type="smtp_auth_plain",
                        username=user,
                        password=pwd,
                        confidence="high",
                        severity="CRITICAL",
                        raw_snippet=smtp_plain.group(0).strip()[:100],
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        metadata={"scheme": "PLAIN"}
                    )
            except (binascii.Error, UnicodeDecodeError):
                pass

        return None
