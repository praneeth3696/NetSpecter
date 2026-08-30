"""
NetSpecter Consolidated Test Suite
==================================
Verifies full protocol detector coverage, stream reassembly, and PCAP analysis.
"""

from __future__ import annotations
import os
import sys
import tempfile
import base64

# Ensure parent directory is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.models import DetectionResult, SessionStats
from core.detector_engine import DetectorEngine
from core.stream_reassembler import TCPStreamReassembler
from detectors.ftp_detector import FTPDetector
from detectors.mail_detector import MailDetector
from detectors.redis_detector import RedisDetector
from detectors.token_detector import TokenDetector
from sniffer import analyze_pcap

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from scapy.all import Ether, IP, TCP, Raw, wrpcap, conf
    conf.verb = 0
except ImportError:
    wrpcap = None

if os.name == "nt":
    os.system("")

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"
BOLD = "\033[1m"


def run_all_tests() -> bool:
    print(f"\n{BOLD}============================================================{RESET}")
    print(f"{BOLD}         NetSpecter v2.0 Comprehensive Test Suite          {RESET}")
    print(f"{BOLD}============================================================{RESET}\n")

    passed = 0
    failed = 0

    def check(name: str, condition: bool, details: str = ""):
        nonlocal passed, failed
        if condition:
            passed += 1
            print(f"  [{GREEN}PASS{RESET}] {name}")
        else:
            failed += 1
            print(f"  [{RED}FAIL{RESET}] {name}")
            if details:
                print(f"         {YELLOW}{details}{RESET}")

    engine = DetectorEngine()

    # --- 1. HTTP Detection Regression (Sample) ---
    res_http = engine.inspect_payload(
        b"POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=admin&password=SuperSecretPassword123!"
    )
    check("HTTP Form Credential Detection", res_http is not None and res_http.username == "admin" and res_http.password == "SuperSecretPassword123!")

    res_json = engine.inspect_payload(
        b'POST /api/auth HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{"user": "secops", "password": "SecurePassword456!"}'
    )
    check("HTTP JSON Credential Detection", res_json is not None and res_json.username == "secops" and res_json.password == "SecurePassword456!")

    res_cookie = engine.inspect_payload(
        b"GET /dashboard HTTP/1.1\r\nHost: internal.corp\r\nCookie: sessionid=ab12cd34ef56gh78ij90kl;\r\n\r\n"
    )
    check("Insecure HTTP Session Cookie Detection", res_cookie is not None and res_cookie.detection_type == "cookie_leak")

    # --- 2. FTP Protocol Detection ---
    ftp = FTPDetector()
    ftp.detect("USER testuser\r\n", src_ip="192.168.1.10")
    res_ftp = ftp.detect("PASS ftpSecretPass999\r\n", src_ip="192.168.1.10")
    check(
        "FTP USER/PASS Credentials",
        res_ftp is not None and res_ftp.username == "testuser" and res_ftp.password == "ftpSecretPass999"
    )

    # --- 3. Mail Protocol Detection (SMTP, POP3, IMAP) ---
    mail = MailDetector()
    # SMTP AUTH PLAIN: \0authzid\0authcid\0passwd
    raw_plain = base64.b64encode(b"\x00postmaster\x00smtpPassSecret123").decode()
    res_smtp = mail.detect(f"AUTH PLAIN {raw_plain}\r\n")
    check(
        "SMTP AUTH PLAIN Credentials",
        res_smtp is not None and res_smtp.username == "postmaster" and res_smtp.password == "smtpPassSecret123"
    )

    res_imap = mail.detect("a01 LOGIN user@company.com myImapSecretPass\r\n")
    check(
        "IMAP Cleartext LOGIN Credentials",
        res_imap is not None and res_imap.username == "user@company.com" and res_imap.password == "myImapSecretPass"
    )

    mail.detect("USER popuser\r\n", src_ip="10.0.0.5")
    res_pop = mail.detect("PASS popSecretPass\r\n", src_ip="10.0.0.5")
    check(
        "POP3 USER/PASS Credentials",
        res_pop is not None and res_pop.username == "popuser" and res_pop.password == "popSecretPass"
    )

    # --- 4. Redis Detection ---
    redis = RedisDetector()
    res_redis_inline = redis.detect("AUTH redisSuperPass\r\n")
    check(
        "Redis Inline AUTH Command",
        res_redis_inline is not None and res_redis_inline.password == "redisSuperPass"
    )

    res_redis_resp = redis.detect("*2\r\n$4\r\nAUTH\r\n$9\r\nfoobared1\r\n")
    check(
        "Redis RESP Protocol AUTH",
        res_redis_resp is not None and res_redis_resp.password == "foobared1"
    )

    # --- 5. High-Value Token Signatures ---
    tokens = TokenDetector()
    res_aws = tokens.detect("Authorization: AWS AKIAIOSFODNN7EXAMPLE:signature")
    check(
        "AWS Access Key ID Detection",
        res_aws is not None and res_aws.token == "AKIAIOSFODNN7EXAMPLE"
    )

    res_gh = tokens.detect("git clone https://ghp_1234567890abcdef1234567890abcdef1234@github.com/repo")
    check(
        "GitHub Personal Access Token Detection",
        res_gh is not None and "ghp_" in res_gh.token
    )

    # Valid mock JWT
    jwt_header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    jwt_payload = base64.urlsafe_b64encode(b'{"sub":"1234567890","email":"victim@corp.com","role":"admin"}').decode().rstrip("=")
    jwt_mock = f"Bearer {jwt_header}.{jwt_payload}.signature1234567890"
    res_jwt = tokens.detect(f"Authorization: {jwt_mock}")
    check(
        "JWT Token & Claims Extraction",
        res_jwt is not None and res_jwt.username == "victim@corp.com"
    )

    # --- 6. TCP Stream Reassembly ---
    reassembler = TCPStreamReassembler()
    chunk1 = b"POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nuser=alice&pass"
    chunk2 = b"word=supersecretreassembledpassword"
    
    seg1, stream1 = reassembler.process_segment("192.168.1.5", 50000, "192.168.1.1", 80, 1000, chunk1)
    seg2, stream2 = reassembler.process_segment("192.168.1.5", 50000, "192.168.1.1", 80, 1000 + len(chunk1), chunk2)
    
    res_fragmented = engine.inspect_payload(stream2)
    check(
        "TCP Stream Fragment Reassembly",
        res_fragmented is not None and res_fragmented.password == "supersecretreassembledpassword"
    )

    # --- 7. Offline PCAP Ingestion & Reporting ---
    if wrpcap is not None:
        try:
            with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
                pcap_path = tf.name
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as jf:
                json_path = jf.name
            with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as hf:
                html_path = hf.name

            # Generate synthetic packet in PCAP
            test_pkt = (
                Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") /
                IP(src="192.168.1.200", dst="192.168.1.1") /
                TCP(sport=43210, dport=80, seq=100) /
                Raw(load=b"POST /login HTTP/1.1\r\n\r\nusername=pcapuser&password=pcapSecretPass123")
            )
            wrpcap(pcap_path, [test_pkt])

            # Run PCAP analysis
            analyze_pcap(pcap_path=pcap_path, mask=True, json_out=json_path, html_out=html_path)

            has_json = os.path.exists(json_path) and os.path.getsize(json_path) > 10
            has_html = os.path.exists(html_path) and os.path.getsize(html_path) > 100

            check("Offline PCAP Replay & JSON/HTML Export", has_json and has_html)

            # Cleanup temp files
            for p in (pcap_path, json_path, html_path):
                if os.path.exists(p):
                    os.remove(p)
        except Exception as e:
            check("Offline PCAP Replay & Reporting", False, str(e))

    # --- Summary ---
    total = passed + failed
    print(f"\n{BOLD}============================================================{RESET}")
    print(f"{BOLD}Results: {GREEN}{passed}{RESET}{BOLD}/{total} passed"
          f"{'  (' + str(failed) + ' failed)' if failed else ''}{RESET}\n")

    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
