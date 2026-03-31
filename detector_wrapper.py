from detectors.http_credential_detector import detect_http_credentials

_FAST_KEYWORDS: list[bytes] = [b"user", b"pass", b"login", b"auth", b"token"]

def process_payload(payload_bytes: bytes) -> dict | None:
    """Fast bytes filter and decoder bridge to the core detector API."""
    if not payload_bytes:
        return None

    lower_bytes = payload_bytes.lower()

    # Pre-flight check: return instantly if no keyword is present
    match_found = False
    for kw in _FAST_KEYWORDS:
        if kw in lower_bytes:
            match_found = True
            break
            
    if not match_found:
        return None

    try:
        payload_str = payload_bytes.decode('utf-8', errors='ignore')
    except Exception:
        return None

    return detect_http_credentials(payload_str)
