"""
NetSpecter Token & Cloud Secret Detector
========================================
Detects high-value API keys, Cloud credentials, and JWT tokens in cleartext streams.
"""

from __future__ import annotations
import base64
import json
import re
from typing import Optional
from core.models import DetectionResult

# High-value secret patterns with high confidence signatures
_PATTERNS = [
    (
        "AWS_KEY",
        re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "CRITICAL",
        "AWS Access Key ID exposed in cleartext"
    ),
    (
        "GITHUB_PAT",
        re.compile(r"\b(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{50,85})\b"),
        "CRITICAL",
        "GitHub Personal Access Token exposed in cleartext"
    ),
    (
        "SLACK_TOKEN",
        re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b"),
        "HIGH",
        "Slack Bot/User Token exposed in cleartext"
    ),
    (
        "STRIPE_KEY",
        re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,})\b"),
        "CRITICAL",
        "Stripe Live Secret Key exposed in cleartext"
    ),
]

_RE_JWT = re.compile(
    r"\b(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b"
)


def _decode_jwt_part(segment: str) -> Optional[dict]:
    """Safely decode base64url JWT header or payload."""
    try:
        rem = len(segment) % 4
        if rem > 0:
            segment += "=" * (4 - rem)
        decoded = base64.urlsafe_b64decode(segment.encode("ascii")).decode("utf-8", errors="replace")
        return json.loads(decoded)
    except Exception:
        return None


class TokenDetector:
    """Detects enterprise cloud tokens and JWT authentication tokens."""
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

        # 1. Check known high-value token signatures
        for token_name, regex, severity, desc in _PATTERNS:
            match = regex.search(payload)
            if match:
                token_val = match.group(1)
                snippet = payload[max(0, match.start() - 25): min(len(payload), match.end() + 25)]
                return DetectionResult(
                    protocol="TOKEN",
                    detection_type=token_name.lower(),
                    token=token_val,
                    password=token_val,
                    confidence="high",
                    severity=severity,
                    raw_snippet=snippet.strip(),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    metadata={"description": desc, "type": token_name}
                )

        # 2. Check JSON Web Tokens (JWT)
        jwt_match = _RE_JWT.search(payload)
        if jwt_match:
            jwt_token = jwt_match.group(1)
            parts = jwt_token.split(".")
            header_json = _decode_jwt_part(parts[0]) or {}
            payload_json = _decode_jwt_part(parts[1]) or {}

            # Extract identity or subject if available
            subject = str(payload_json.get("email") or payload_json.get("sub") or payload_json.get("name") or "")
            algo = header_json.get("alg", "unknown")

            snippet = payload[max(0, jwt_match.start() - 20): min(len(payload), jwt_match.end() + 20)]

            return DetectionResult(
                protocol="JWT",
                detection_type="jwt_token",
                username=subject,
                token=jwt_token,
                password=jwt_token,
                confidence="high",
                severity="HIGH",
                raw_snippet=snippet.strip()[:120],
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                metadata={
                    "algorithm": algo,
                    "subject": subject,
                    "claims": list(payload_json.keys())[:8]
                }
            )

        return None
