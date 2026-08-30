# NetSpecter v2.0

```
 ███╗   ██╗███████╗████████╗███████╗██████╗ ███████╗ ██████╗████████╗███████╗██████╗ 
 ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
 ██╔██╗ ██║█████╗     ██║   ███████╗██████╔╝█████╗  ██║        ██║   █████╗  ██████╔╝
 ██║╚██╗██║██╔══╝     ██║   ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══╝  ██╔══██╗
 ██║ ╚████║███████╗   ██║   ███████║██║     ███████╗╚██████╗   ██║   ███████╗██║  ██║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
```

**Real-Time Network Insecurity & Plaintext Credential Leak Auditor**  
*Defensive intrusion analysis, TCP stream reassembly, multi-protocol credential extraction, interactive TUI dashboard, and executive audit reporting.*

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://python.org)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows%2011-cyan.svg)](https://github.com/praneeth3696/NetSpecter)
[![Tests](https://img.shields.io/badge/tests-35%2F35%20passing-brightgreen.svg)](tests/)
[![License](https://img.shields.io/badge/license-MIT-purple.svg)](LICENSE)

---

## Overview

**NetSpecter** is a real-time network traffic auditor and intrusion detection utility engineered to uncover insecure, unencrypted credential transmissions lurking across local networks.

While modern web applications strive for universal encryption, plaintext protocols remain prevalent across legacy internal services, IoT appliances, microservices, container bridges, and staging environments. NetSpecter captures network packets, reconstructs fragmented TCP sessions, applies zero-overhead byte pre-filtering, extracts sensitive credentials and API keys across multiple protocols, and renders alerts through a terminal UI or generates executive HTML audit reports.

---

## Key Features

### 1. Multi-Protocol Credential Inspection
- **HTTP**: POST form data (`x-www-form-urlencoded`), JSON bodies (including nested keys), URL query parameters (GET requests), HTTP Basic Auth (`Authorization: Basic`), Bearer tokens, multipart form data, and embedded URL userinfo (`http://user:pass@host/`).
- **FTP**: Cleartext `USER` and `PASS` commands on port 21.
- **Mail Services**: SMTP (`AUTH PLAIN` and `AUTH LOGIN`), POP3 (`USER` and `PASS`), and IMAP (`LOGIN`).
- **Redis**: Unencrypted `AUTH <password>` commands (inline and RESP protocols).
- **Insecure Cookies**: Intercepts `sessionid`, `PHPSESSID`, `JSESSIONID`, `connect.sid`, and `auth_token` values transmitted over unencrypted HTTP.

### 2. High-Value Cloud & API Secret Scanner
- **AWS Access Keys**: Identifies `AKIA[0-9A-Z]{16}` tokens.
- **GitHub Personal Access Tokens**: Detects `ghp_...` and `github_pat_...` tokens.
- **Slack Tokens**: Identifies `xoxb-`, `xoxp-`, and `xoxa-` authentication tokens.
- **Stripe Keys**: Detects `sk_live_...` secret production keys.
- **JSON Web Tokens (JWT)**: Decodes base64 header and claims in real-time, extracting subjects, roles, and email addresses.

### 3. Advanced Engine & Forensic Capabilities
- **TCP Stream Reassembly**: Tracks IP 5-tuples (`src_ip, src_port, dst_ip, dst_port, TCP`) and stitches fragmented segments across MTU boundaries to catch split-packet credentials.
- **Offline PCAP / PCAPNG Analysis**: Forensic post-incident replay mode (`netspecter pcap <file>`) to audit captures without requiring raw socket access.
- **Interactive Cyber TUI Dashboard**: Real-time Rich Live dashboard featuring packet counters, throughput rate, active flow monitor, and live incident feed.
- **Credential Redaction / Masking**: Defaults to safe masked output (`admin: s3c****t`) for live demos and recordings, with `--show-secrets` for full visibility.
- **Enterprise Reporting**: Exports findings as structured JSON (`--json-out`) and self-contained executive HTML audit reports (`--html-out`) with remediation advisories.
- **Full Cross-Platform Support**: Seamless operation on **Windows 11 / 10**, **Linux** (Ubuntu, Kali, Debian, Arch), and **macOS** (Darwin).

---

## Installation & Requirements

### 1. Packet Capture Drivers (Per OS)

- **Windows 11 / 10**:
  - Download and install **Npcap** from [https://npcap.com](https://npcap.com).
  - *Important*: During installation, check **"Install Npcap in WinPcap API-compatible Mode"**.
- **Linux (Ubuntu / Debian / Kali)**:
  - `sudo apt update && sudo apt install libpcap-dev`
- **macOS**:
  - Built-in BPF support (`/dev/bpf*`). Optional update via Homebrew: `brew install libpcap`

### 2. Setup

#### Linux / macOS:
```bash
git clone https://github.com/praneeth3696/NetSpecter.git
cd NetSpecter

# Set up virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

#### Windows 11 (PowerShell / Command Prompt as Administrator):
```powershell
git clone https://github.com/praneeth3696/NetSpecter.git
cd NetSpecter

# Set up virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

---

## CLI Usage & Commands

```
usage: netspecter [-h] {scan,pcap,interfaces,test} ...
```

### 1. Live Sniffing (`scan`)
Sniff live traffic on the default or specified interface (requires `sudo` on Linux/macOS or Administrator prompt on Windows):

**Linux / macOS:**
```bash
# Auto-detect default network interface
sudo python3 main.py scan

# Specify interface with custom BPF filter
sudo python3 main.py scan --iface eth0 --bpf "tcp port 80 or tcp port 21"

# Launch interactive full-screen Cyber TUI dashboard
sudo python3 main.py scan --dashboard

# Generate both JSON and Executive HTML reports upon exit
sudo python3 main.py scan --json-out audit.json --html-out report.html

# Reveal full secrets without terminal masking
sudo python3 main.py scan --show-secrets
```

**Windows 11 (Elevated PowerShell / Terminal):**
```powershell
# Auto-detect default network interface
python main.py scan

# Specify friendly adapter name (e.g. "Wi-Fi" or "Ethernet")
python main.py scan --iface "Wi-Fi" --dashboard

# Export findings to HTML and JSON reports upon exit
python main.py scan --html-out report.html --json-out audit.json
```

### 2. Offline PCAP Forensic Analysis (`pcap`)
Analyze captured `.pcap` or `.pcapng` files without root privileges:

```bash
# Analyze capture and display incident cards
python3 main.py pcap samples/demo_traffic.pcap

# Export forensic findings to HTML report and JSON
python3 main.py pcap samples/demo_traffic.pcap --html-out forensic_report.html --json-out forensic.json
```

### 3. List Network Interfaces (`interfaces`)
View an overview table of host interfaces with IPv4, MAC, and operational status:

```bash
python3 main.py interfaces
```

### 4. Self-Test Suite (`test`)
Execute the built-in test suite covering all protocols, stream reassembly, and PCAP replay:

```bash
python3 main.py test
```

---

## Architecture

```
NetSpecter/
├── core/
│   ├── models.py                 # Typed models: DetectionResult, FlowKey, SessionStats
│   ├── stream_reassembler.py     # TCP flow table & multi-packet reassembly
│   └── detector_engine.py        # Central dispatcher with byte-level pre-filter
├── detectors/
│   ├── http_credential_detector.py # HTTP forms, JSON, headers, cookies, query
│   ├── ftp_detector.py           # FTP USER/PASS parser
│   ├── mail_detector.py          # SMTP AUTH, POP3, IMAP LOGIN parser
│   ├── redis_detector.py         # Redis inline & RESP AUTH parser
│   └── token_detector.py         # AWS, GitHub, Slack, Stripe & JWT detector
├── reporting/
│   └── reporter.py               # JSON/JSONL exporter & Executive HTML report builder
├── ui/
│   └── dashboard.py              # Interactive Rich Live TUI dashboard
├── samples/
│   └── demo_traffic.pcap         # Multi-protocol demonstration PCAP fixture
├── tests/
│   ├── test_suite.py             # Comprehensive system & protocol test suite
│   └── test_http_credential_detector.py # 21 HTTP regression tests
├── formatter.py                  # Cyberpunk styling, alert panels & summaries
├── sniffer.py                    # Live packet capture & offline PCAP engine
├── main.py                       # CLI entry point & subcommands
└── requirements.txt              # Production dependencies
```

---

## Example Incident Alert

When plaintext credentials or sensitive tokens are intercepted, NetSpecter renders a glowing alert card:

```
╭───────────── ⚠️  INSECURE CREDENTIAL TRANSMISSION DETECTED  ⚠️ ──────────────╮
│                                                                              │
│           Protocol:  HTTP (form)                                             │
│           Severity:   CRITICAL                                               │
│        Source Host:  10.0.0.15:51234                                         │
│        Target Host:  198.51.100.2:80                                         │
│      Username / ID:  admin                                                   │
│     Exposed Secret:  C****************!                                      │
│         Confidence:  HIGH                                                    │
│        Raw Payload:  username=admin&password=CompanySecret2026!              │
│                                                                              │
╰────── Plaintext transmission vulnerable to passive wiretapping & MITM ───────╯
```

---

## Testing & Quality Assurance

NetSpecter includes an automated test suite verifying 100% detector accuracy across all supported protocols:

```bash
# Run comprehensive system tests (14/14 passing)
python3 main.py test

# Run legacy HTTP regression tests (21/21 passing)
python3 tests/test_http_credential_detector.py
```

---

## Disclaimer

> **Warning**: NetSpecter is designed exclusively for authorized network auditing, defensive intrusion detection, educational demonstrations, and vulnerability research. You must never monitor network traffic on infrastructure where you do not possess explicit, written permission from the network owner.

---

## Author

**Praneeth** ([@praneeth3696](https://github.com/praneeth3696))
