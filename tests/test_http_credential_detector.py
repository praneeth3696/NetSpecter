"""
NetSpecter — HTTP Credential Detector Test Suite
================================================
Run with: python -m pytest tests/test_http_credential_detector.py -v
or:        python tests/test_http_credential_detector.py
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detectors.http_credential_detector import (
    detect_http_credentials,
    detect_all_http_credentials,
)


# ---------------------------------------------------------------------------
# ANSI helpers for standalone run
# ---------------------------------------------------------------------------
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

passed = 0
failed = 0

def run(test_name: str, payload: str, expect_detection: bool,
        expected_type: str | None = None,
        expected_confidence: str | None = None,
        note: str = ""):
    global passed, failed
    result = detect_http_credentials(payload)
    detected = result is not None
    ok = detected == expect_detection

    if ok and expected_type and result:
        ok = result.get("type") == expected_type
    if ok and expected_confidence and result:
        ok = result.get("confidence") == expected_confidence

    status = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
    if ok:
        passed += 1
    else:
        failed += 1

    print(f"  [{status}] {test_name}")
    if not ok:
        print(f"         Expected detected={expect_detection} type={expected_type} confidence={expected_confidence}")
        print(f"         Got     : {result}")
    elif result:
        print(f"         → type={result['type']!r}  user={result['username']!r}"
              f"  pass={result['password']!r}  conf={result['confidence']!r}")
    if note:
        print(f"         {YELLOW}note: {note}{RESET}")


# ===========================================================================
# TEST CASES
# ===========================================================================

print(f"\n{BOLD}NetSpecter — HTTP Credential Detector Tests{RESET}")
print("=" * 60)

# ---------------------------------------------------------------------------
print(f"\n{BOLD}1. Form-urlencoded (POST body){RESET}")
# ---------------------------------------------------------------------------

run(
    "TC-01 Standard login form",
    payload="POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=alice&password=s3cret&remember=1",
    expect_detection=True,
    expected_type="form",
    expected_confidence="high",
)

run(
    "TC-02 URL-encoded characters in password",
    payload="user=bob&passwd=p%40ssw%21rd&login=1",
    expect_detection=True,
    expected_type="form",
    note="Password contains percent-encoded @ and !",
)

run(
    "TC-03 Unusual key names (uid / pwd)",
    payload="uid=carol&pwd=Hunter2!&submit=Login",
    expect_detection=True,
    expected_type="form",
    expected_confidence="high",
)

# ---------------------------------------------------------------------------
print(f"\n{BOLD}2. JSON body{RESET}")
# ---------------------------------------------------------------------------

run(
    "TC-04 Standard JSON credentials",
    payload='POST /api/auth HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{"username":"dave","password":"correcthorsebattery"}',
    expect_detection=True,
    expected_type="json",
    expected_confidence="high",
)

run(
    "TC-05 Nested JSON (one level)",
    payload='{"user":{"login":"eve","secret":"Pa$$w0rd!"},"rememberMe":true}',
    expect_detection=True,
    expected_type="json",
    note="Nested under 'user' object",
)

run(
    "TC-06 JSON with API key",
    payload='{"api_key":"sk-4f9a3b2c1d0e8f7g6h5i4j3k2l1m0n9o","action":"subscribe"}',
    expect_detection=True,
    expected_type="json",
    note="API key detected even without a username field",
)

# ---------------------------------------------------------------------------
print(f"\n{BOLD}3. HTTP Basic Authorization header{RESET}")
# ---------------------------------------------------------------------------

import base64

_basic_token = base64.b64encode(b"frank:mypassword123").decode()

run(
    "TC-07 Authorization: Basic",
    payload=f"GET /protected HTTP/1.1\r\nHost: example.com\r\nAuthorization: Basic {_basic_token}\r\n\r\n",
    expect_detection=True,
    expected_type="header_basic",
    expected_confidence="high",
)

run(
    "TC-08 Basic Auth — trivial password",
    payload=f"GET /resource HTTP/1.1\r\nAuthorization: Basic {base64.b64encode(b'admin:admin').decode()}\r\n\r\n",
    expect_detection=True,
    expected_type="header_basic",
    expected_confidence="medium",
    note="Low-entropy password drops confidence",
)

# ---------------------------------------------------------------------------
print(f"\n{BOLD}4. Bearer / Token headers{RESET}")
# ---------------------------------------------------------------------------

run(
    "TC-09 Bearer token",
    payload="GET /api/data HTTP/1.1\r\nAuthorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.hmac\r\n",
    expect_detection=True,
    expected_type="header_bearer",
    expected_confidence="high",
)

# ---------------------------------------------------------------------------
print(f"\n{BOLD}5. URL query parameters (GET){RESET}")
# ---------------------------------------------------------------------------

run(
    "TC-10 Password in GET query string",
    payload="GET /login?email=grace%40example.com&password=opensesame&next=%2Fdashboard HTTP/1.1\r\nHost: example.com\r\n\r\n",
    expect_detection=True,
    expected_type="query",
    expected_confidence="high",
    note="Credentials passed in GET — extremely insecure",
)

run(
    "TC-11 API key in query string",
    payload="GET /v1/data?api_key=abc123supersecretkey&format=json HTTP/1.1\r\nHost: api.example.com\r\n",
    expect_detection=True,
    note="api_key in query string",
)

# ---------------------------------------------------------------------------
print(f"\n{BOLD}6. multipart/form-data{RESET}")
# ---------------------------------------------------------------------------

run(
    "TC-12 Multipart login form",
    payload=(
        "POST /login HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=----FormBoundary\r\n\r\n"
        "------FormBoundary\r\n"
        'Content-Disposition: form-data; name="username"\r\n'
        "\r\n"
        "henry\r\n"
        "------FormBoundary\r\n"
        'Content-Disposition: form-data; name="password"\r\n'
        "\r\n"
        "hunter2!!\r\n"
        "------FormBoundary--\r\n"
    ),
    expect_detection=True,
    expected_type="multipart",
    expected_confidence="high",
)

# ---------------------------------------------------------------------------
print(f"\n{BOLD}7. URL userinfo credentials{RESET}")
# ---------------------------------------------------------------------------

run(
    "TC-13 Credentials embedded in URL",
    payload="GET http://alice:s3cr3t@internal.company.com/api/reports HTTP/1.0\r\n",
    expect_detection=True,
    expected_type="url_userinfo",
    expected_confidence="high",
)

# ---------------------------------------------------------------------------
print(f"\n{BOLD}8. Edge cases & false positives{RESET}")
# ---------------------------------------------------------------------------

run(
    "TC-14 Clean HTTP response — no credentials",
    payload="HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Welcome!</body></html>",
    expect_detection=False,
    note="Plain response body — should NOT trigger",
)

run(
    "TC-15 JSON with unrelated 'token' field (game item token)",
    payload='{"itemType":"sword","token":"3","level":42,"xp":800}',
    expect_detection=True,          # 'token' IS in our list — acknowledged FP
    note="Short numeric 'token=3' — will be low confidence due to short value",
)

run(
    "TC-16 Partial / split packet (password cut off)",
    payload="username=ivan&passw",    # packet fragment
    expect_detection=False,
    note="Truncated key — should not match incomplete word 'passw'",
)

run(
    "TC-17 Empty payload",
    payload="",
    expect_detection=False,
)

run(
    "TC-18 Non-HTTP binary-like garbage",
    payload="\x00\x01\x02\x03\xff\xfe\xfd",
    expect_detection=False,
)

run(
    "TC-19 Form data without password field",
    payload="search=hello+world&category=news&page=2",
    expect_detection=False,
    note="Form data with no credential keys — must not false-positive",
)

run(
    "TC-20 JSON body — only username, no password field",
    payload='{"username":"jenny","action":"profile_view"}',
    expect_detection=False,
    note="Username without any secret field — must not false-positive",
)

# ---------------------------------------------------------------------------
print(f"\n{BOLD}9. detect_all_http_credentials() — multi-match{RESET}")
# ---------------------------------------------------------------------------

multi_payload = (
    f"POST /login HTTP/1.1\r\n"
    f"Authorization: Basic {base64.b64encode(b'admin:pass123').decode()}\r\n"
    f"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
    f"username=admin&password=pass123"
)
all_results = detect_all_http_credentials(multi_payload)
multi_ok = len(all_results) >= 2
status = f"{GREEN}PASS{RESET}" if multi_ok else f"{RED}FAIL{RESET}"
if multi_ok:
    passed += 1
else:
    failed += 1
print(f"  [{status}] TC-21 Multi-match: Basic header + form body")
print(f"         Found {len(all_results)} result(s): {[r['type'] for r in all_results]}")


# ---------------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------------
total = passed + failed
print(f"\n{'=' * 60}")
print(f"{BOLD}Results: {GREEN}{passed}{RESET}{BOLD}/{total} passed"
      f"{'  (' + str(failed) + ' failed)' if failed else ''}{RESET}")
print()
