"""
NetSpecter — HTTP Credential Leak Detector
==========================================
Module  : detectors/http_credential_detector.py
Author  : NetSpecter Security Team
Purpose : Real-time detection of plaintext credential transmission over HTTP.

Supports:
  - application/x-www-form-urlencoded (POST form data)
  - JSON payloads (application/json)
  - URL query parameters (GET requests)
  - HTTP Basic Auth header (Authorization: Basic ...)
  - Bearer / Token header patterns
  - multipart/form-data field extraction
  - URL-encoded and partial/split packet edge cases

Return contract:
  dict | None
  {
    "type"       : str   – "form" | "json" | "query" | "header_basic" | "header_token" | "multipart",
    "username"   : str   – extracted username (or "" if not applicable),
    "password"   : str   – extracted credential value,
    "confidence" : str   – "low" | "medium" | "high",
    "raw_snippet": str   – ≤200-char window around the match,
  }
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import urllib.parse
from typing import Optional

# ---------------------------------------------------------------------------
# ❶  CREDENTIAL FIELD NAME LISTS
# ---------------------------------------------------------------------------

# Username field names encountered in the wild (case-insensitive)
_USERNAME_KEYS: set[str] = {
    "username", "user", "user_name", "uname", "login", "email",
    "user_email", "account", "userId", "user_id", "uid",
    "handle", "identifier", "principal", "member",
}

# Password / secret field names (case-insensitive)
_PASSWORD_KEYS: set[str] = {
    "password", "passwd", "pass", "pwd", "secret", "token",
    "api_key", "apikey", "api_token", "access_token", "auth_token",
    "credentials", "credential", "auth", "key", "pin",
    "otp", "passphrase", "passcode", "code", "hash",
    "client_secret", "refresh_token", "session_token",
}

# Compile lowercase versions for fast lookups
_USERNAME_KEYS_LOWER: set[str] = {k.lower() for k in _USERNAME_KEYS}
_PASSWORD_KEYS_LOWER: set[str] = {k.lower() for k in _PASSWORD_KEYS}

# ---------------------------------------------------------------------------
# ❷  PRE-COMPILED REGEXES
# ---------------------------------------------------------------------------

# HTTP Authorization header — Basic scheme
_RE_AUTH_BASIC = re.compile(
    r"Authorization\s*:\s*Basic\s+([A-Za-z0-9+/=]{8,})",
    re.IGNORECASE,
)

# HTTP Authorization header — Bearer / Token schemes (credential token)
_RE_AUTH_BEARER = re.compile(
    r"Authorization\s*:\s*(Bearer|Token)\s+([A-Za-z0-9\-._~+/=]{16,})",
    re.IGNORECASE,
)

# HTTP Basic Auth embedded in URL  e.g. http://user:pass@host/
_RE_URL_USERINFO = re.compile(
    r"https?://([^:@/\s]{1,64}):([^@/\s]{1,128})@",
    re.IGNORECASE,
)

# Multipart Content-Disposition field name
_RE_MULTIPART_FIELD = re.compile(
    r'Content-Disposition\s*:[^\n]*name="([^"]+)"',
    re.IGNORECASE,
)

# Boundary line in multipart payload
_RE_MULTIPART_BOUNDARY = re.compile(
    r"boundary=([^\s;,\"]+)",
    re.IGNORECASE,
)

# Detect if payload looks like a raw HTTP message (has verb + protocol line)
_RE_HTTP_REQUEST_LINE = re.compile(
    r"^(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+\S+\s+HTTP/\d",
    re.IGNORECASE | re.MULTILINE,
)

# Fast scan: does the payload contain any credential-like key at all?
# Used as a cheap pre-filter before heavier parsing.
_ALL_CRED_KEYS = _USERNAME_KEYS_LOWER | _PASSWORD_KEYS_LOWER
_RE_QUICK_SCAN = re.compile(
    r"\b(" + "|".join(re.escape(k) for k in sorted(_ALL_CRED_KEYS)) + r")\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# ❸  HELPER UTILITIES
# ---------------------------------------------------------------------------

def _snippet(payload: str, match: re.Match, window: int = 200) -> str:
    """Return a short context window around a regex match."""
    start = max(0, match.start() - 30)
    end   = min(len(payload), match.end() + window)
    return payload[start:end]


def _normalize_key(key: str) -> str:
    return key.strip().lower().replace("-", "_").replace(" ", "_")


def _is_password_key(key: str) -> bool:
    return _normalize_key(key) in _PASSWORD_KEYS_LOWER


def _is_username_key(key: str) -> bool:
    return _normalize_key(key) in _USERNAME_KEYS_LOWER


def _confidence_from_pair(username: str, password: str) -> str:
    """
    Heuristic confidence scoring:
      high   → both username and password found, password is non-trivial
      medium → only password found and it looks realistic
      low    → field name matched but value is very short or looks like a placeholder
    """
    if not password:
        return "low"

    trivial_passwords = {"password", "pass", "123456", "qwerty", "test", "admin"}
    is_trivial = password.lower() in trivial_passwords or len(password) < 4

    if username and not is_trivial:
        return "high"
    if username and is_trivial:
        return "medium"
    if not username and not is_trivial:
        return "medium"
    return "low"


def _safe_url_decode(value: str) -> str:
    """Decode percent-encoding; return original string on failure."""
    try:
        return urllib.parse.unquote_plus(value)
    except Exception:
        return value


# ---------------------------------------------------------------------------
# ❹  DETECTION SUBSYSTEMS
# ---------------------------------------------------------------------------

# ── 4a. application/x-www-form-urlencoded ───────────────────────────────────

def _detect_form_urlencoded(payload: str) -> Optional[dict]:
    """
    Detects credentials in POST body form data.
    Example: username=alice&password=s3cret&remember=1
    """
    # Isolate the body portion (after double newline if full HTTP message)
    body = _extract_body(payload)
    if not body:
        return None

    # Must look like key=value& pairs; bail if it starts with { or <
    stripped = body.strip()
    if stripped.startswith(("{", "<", "[")):
        return None

    try:
        params: dict[str, list[str]] = urllib.parse.parse_qs(
            stripped, keep_blank_values=True, strict_parsing=False
        )
    except Exception:
        return None

    if not params:
        return None

    username = ""
    password = ""
    matched_snippet = stripped[:200]

    for key, values in params.items():
        value = _safe_url_decode(values[0]) if values else ""
        if _is_password_key(key) and not password:
            password = value
        if _is_username_key(key) and not username:
            username = value

    if not password:
        return None

    return {
        "type"       : "form",
        "username"   : username,
        "password"   : password,
        "confidence" : _confidence_from_pair(username, password),
        "raw_snippet": matched_snippet,
    }


# ── 4b. JSON payload ────────────────────────────────────────────────────────

def _detect_json(payload: str) -> Optional[dict]:
    """
    Detects credentials in JSON bodies.
    Example: {"user": "alice", "password": "s3cret"}
    Also handles nested objects (one level deep).
    """
    body = _extract_body(payload)
    if not body:
        return None

    stripped = body.strip()
    if not stripped.startswith("{"):
        return None

    try:
        # Attempt to find the JSON object even if there's trailing garbage
        brace_end = stripped.rfind("}")
        if brace_end == -1:
            return None
        data = json.loads(stripped[: brace_end + 1])
    except (json.JSONDecodeError, ValueError):
        return None

    if not isinstance(data, dict):
        return None

    def _flatten(d: dict, prefix: str = "") -> dict:
        """Flatten one level of nesting."""
        out: dict[str, str] = {}
        for k, v in d.items():
            full_key = f"{prefix}{k}" if not prefix else f"{prefix}.{k}"
            if isinstance(v, (str, int, float, bool)):
                out[full_key] = str(v)
            elif isinstance(v, dict):
                out.update(_flatten(v, full_key))
        return out

    flat = _flatten(data)

    username = ""
    password = ""

    for key, value in flat.items():
        bare_key = key.split(".")[-1]          # ignore prefix for matching
        if _is_password_key(bare_key) and not password:
            password = value
        if _is_username_key(bare_key) and not username:
            username = value

    if not password:
        return None

    return {
        "type"       : "json",
        "username"   : username,
        "password"   : password,
        "confidence" : _confidence_from_pair(username, password),
        "raw_snippet": stripped[:200],
    }


# ── 4c. URL query string (GET requests) ─────────────────────────────────────

def _detect_query_params(payload: str) -> Optional[dict]:
    """
    Detects credentials embedded in URL query strings.
    Example: GET /login?username=alice&password=s3cret HTTP/1.1
    """
    # Extract the request line
    m = _RE_HTTP_REQUEST_LINE.search(payload)
    if not m:
        # Try matching a bare URL with query string
        url_match = re.search(r"\?([^\s#\"<>]{4,})", payload)
        if not url_match:
            return None
        qs = url_match.group(1)
        snippet = url_match.group(0)[:200]
    else:
        # Parse URL from the request line
        line = payload[m.start(): payload.find("\n", m.start())]
        url_part_match = re.search(r"\S+\?(\S+)\s", line)
        if not url_part_match:
            return None
        qs = url_part_match.group(1)
        snippet = line[:200]

    try:
        params = urllib.parse.parse_qs(qs, keep_blank_values=True)
    except Exception:
        return None

    username = ""
    password = ""

    for key, values in params.items():
        value = _safe_url_decode(values[0]) if values else ""
        if _is_password_key(key) and not password:
            password = value
        if _is_username_key(key) and not username:
            username = value

    if not password:
        return None

    return {
        "type"       : "query",
        "username"   : username,
        "password"   : password,
        "confidence" : _confidence_from_pair(username, password),
        "raw_snippet": snippet,
    }


# ── 4d. HTTP Authorization: Basic header ────────────────────────────────────

def _detect_header_basic(payload: str) -> Optional[dict]:
    """
    Detects HTTP Basic Auth credentials.
    Example: Authorization: Basic YWxpY2U6czNjcmV0
    """
    m = _RE_AUTH_BASIC.search(payload)
    if not m:
        return None

    b64_value = m.group(1)
    try:
        decoded = base64.b64decode(b64_value + "==").decode("utf-8", errors="replace")
    except (binascii.Error, UnicodeDecodeError):
        return None

    if ":" not in decoded:
        # Malformed — might still be a token, treat as low-confidence
        return {
            "type"       : "header_basic",
            "username"   : "",
            "password"   : decoded,
            "confidence" : "low",
            "raw_snippet": _snippet(payload, m),
        }

    username, _, password = decoded.partition(":")
    return {
        "type"       : "header_basic",
        "username"   : username,
        "password"   : password,
        "confidence" : _confidence_from_pair(username, password),
        "raw_snippet": _snippet(payload, m),
    }


# ── 4e. Bearer / Token header ───────────────────────────────────────────────

def _detect_header_token(payload: str) -> Optional[dict]:
    """
    Detects Bearer/Token authorization headers.
    Example: Authorization: Bearer eyJhbGciOi...
    These are access tokens, not passwords, but still sensitive.
    """
    m = _RE_AUTH_BEARER.search(payload)
    if not m:
        return None

    scheme = m.group(1)
    token  = m.group(2)

    return {
        "type"       : f"header_{scheme.lower()}",
        "username"   : "",
        "password"   : token,
        "confidence" : "high",          # Bearer tokens are always sensitive
        "raw_snippet": _snippet(payload, m),
    }


# ── 4f. URL user-info credentials ───────────────────────────────────────────

def _detect_url_userinfo(payload: str) -> Optional[dict]:
    """
    Detects credentials embedded in URLs.
    Example: http://alice:s3cret@api.example.com/v1/data
    """
    m = _RE_URL_USERINFO.search(payload)
    if not m:
        return None

    username = _safe_url_decode(m.group(1))
    password = _safe_url_decode(m.group(2))

    return {
        "type"       : "url_userinfo",
        "username"   : username,
        "password"   : password,
        "confidence" : _confidence_from_pair(username, password),
        "raw_snippet": _snippet(payload, m),
    }


# ── 4g. multipart/form-data ─────────────────────────────────────────────────

def _detect_multipart(payload: str) -> Optional[dict]:
    """
    Detects credentials in multipart/form-data bodies.
    Parses field name / value pairs from MIME boundaries.

    Example:
      --boundary\\r\\n
      Content-Disposition: form-data; name="password"\\r\\n
      \\r\\n
      s3cret\\r\\n
      --boundary--
    """
    username = ""
    password = ""
    snippet  = ""

    # Split on lines to find boundary markers
    lines = payload.splitlines()
    current_field: Optional[str] = None
    reading_value  = False

    for i, line in enumerate(lines):
        stripped_line = line.strip()

        # Boundary line resets state
        if stripped_line.startswith("--"):
            current_field  = None
            reading_value  = False
            continue

        # Content-Disposition header identifies the field name
        field_match = _RE_MULTIPART_FIELD.search(line)
        if field_match:
            current_field = field_match.group(1)
            reading_value = False
            continue

        # Blank line = value body starts next
        if stripped_line == "" and current_field:
            reading_value = True
            continue

        # Capture the field value
        if reading_value and current_field:
            value = stripped_line
            if _is_password_key(current_field) and not password:
                password = value
                snippet  = f'name="{current_field}": {value}'
            if _is_username_key(current_field) and not username:
                username = value
            reading_value = False
            current_field = None

    if not password:
        return None

    return {
        "type"       : "multipart",
        "username"   : username,
        "password"   : password,
        "confidence" : _confidence_from_pair(username, password),
        "raw_snippet": snippet[:200],
    }


# ---------------------------------------------------------------------------
# ❺  BODY EXTRACTOR
# ---------------------------------------------------------------------------

def _extract_body(payload: str) -> str:
    """
    If payload is a full HTTP message, return only the body portion.
    Otherwise return the whole payload (already-extracted body).
    The split is the first double CRLF or double LF sequence.
    """
    for sep in ("\r\n\r\n", "\n\n"):
        if sep in payload:
            return payload.split(sep, 1)[1]
    return payload


# ---------------------------------------------------------------------------
# ❻  QUICK PRE-FILTER
# ---------------------------------------------------------------------------

def _quick_scan(payload: str) -> bool:
    """
    Cheap O(n) pre-filter: returns True only if the payload contains at
    least one known credential key word, an Authorization header, or a
    URL userinfo pattern (http://user:pass@host).
    This avoids expensive parsing on every packet.
    """
    lower = payload.lower()
    if "authorization" in lower:
        return True
    # URL userinfo:  http(s)://something:something@
    if "://" in lower and "@" in lower:
        return True
    return bool(_RE_QUICK_SCAN.search(lower))


# ---------------------------------------------------------------------------
# ❼  MAIN PUBLIC FUNCTION
# ---------------------------------------------------------------------------

def detect_http_credentials(payload: str) -> dict | None:
    """
    Scan a decoded HTTP payload string for credential leakage.

    Args:
        payload: Raw decoded HTTP packet payload (headers + body, or body only).

    Returns:
        A detection dict if credentials found, else None.
        Dict schema:
        {
            "type"       : str,   # Source format of the credential
            "username"   : str,   # Extracted username (may be empty)
            "password"   : str,   # Extracted credential / token
            "confidence" : str,   # "low" | "medium" | "high"
            "raw_snippet": str,   # Context window (≤200 chars)
        }

    Performance:
        - Pre-filtered by fast keyword scan — avoids regex overhead on clean traffic.
        - All sub-detectors are independent; first non-None result wins.
        - No external I/O; safe for hot paths.
    """
    if not payload or not isinstance(payload, str):
        return None

    # ── Fast pre-filter ───────────────────────────────────────────────────
    if not _quick_scan(payload):
        return None

    # ── Run detectors in priority order ───────────────────────────────────
    # Headers are checked first (most explicit signal).
    # Then structured body formats. Query params last (higher FP rate).

    detectors = [
        _detect_header_basic,
        _detect_header_token,
        _detect_url_userinfo,
        _detect_json,
        _detect_form_urlencoded,
        _detect_multipart,
        _detect_query_params,
    ]

    for detector in detectors:
        try:
            result = detector(payload)
            if result:
                return result
        except Exception:
            # Never crash the packet capture loop
            continue

    return None


# ---------------------------------------------------------------------------
# ❽  CONVENIENCE: MULTI-RESULT MODE
# ---------------------------------------------------------------------------

def detect_all_http_credentials(payload: str) -> list[dict]:
    """
    Like detect_http_credentials() but returns ALL matches found across
    every detector (useful for payloads that embed credentials in multiple
    locations simultaneously).
    """
    if not payload or not isinstance(payload, str):
        return []

    if not _quick_scan(payload):
        return []

    detectors = [
        _detect_header_basic,
        _detect_header_token,
        _detect_url_userinfo,
        _detect_json,
        _detect_form_urlencoded,
        _detect_multipart,
        _detect_query_params,
    ]

    results = []
    for detector in detectors:
        try:
            result = detector(payload)
            if result:
                results.append(result)
        except Exception:
            continue

    return results
