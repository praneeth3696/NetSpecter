import argparse
import sys
import os
from formatter import print_error, print_alert, print_info
from sniffer import start_sniffing

def check_posix():
    """Ensure Linux context"""
    if os.name != "posix":
        print_error("NetSpecter requires Linux (Ubuntu/Kali).")
        sys.exit(1)

def check_root():
    """Fail if not root (EUID 0). Raw sockets demand root access."""
    if os.geteuid() != 0:
        print_error("NetSpecter requires root privileges (sudo).")
        sys.exit(1)

def parse_args():
    parser = argparse.ArgumentParser(
        prog="netspecter",
        description="NetSpecter: Real-Time Insecure Transmission Detection"
    )
    
    subparsers = parser.add_subparsers(
        dest="command",
        required=True
    )
    
    scan_parser = subparsers.add_parser(
        "scan", 
        help="Sniff readable traffic looking for raw HTML/JSON credential leaks"
    )
    scan_parser.add_argument(
        "--iface",
        type=str,
        default=None,
        dest="iface",
        help="Specify target interface (e.g., eth0). Auto-detects if unset."
    )

    return parser.parse_args()

def main():
    try:
        args = parse_args()
        if args.command == "scan":
            check_posix()
            check_root()
            start_sniffing(iface=args.iface)
    except Exception as e:
        print_error(str(e))
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # Capture simple Ctrl+C exits gracefully during args logic
        sys.exit(0)
