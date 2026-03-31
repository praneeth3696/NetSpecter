# NetSpecter CLI

Real-time network traffic analysis tool to detect insecure credential transmission over HTTP.

---

## Overview

NetSpecter CLI is a Linux-based cybersecurity tool that monitors live network traffic and identifies insecure transmission of credentials over plaintext protocols like HTTP and Telnet. 

It uses packet inspection to detect sensitive data such as usernames and passwords being transmitted without encryption and alerts the user in real time.

---

## Features

- **Real-time packet sniffing** using Scapy
- **Detects plaintext credential leaks** (HTTP, Telnet)
- **Supports multiple formats:**
  - Form data (`username=...&password=...`)
  - JSON payloads
  - Basic Auth headers
  - URL Query parameters
  - Multipart form data
- **Optimized detection** using fast byte-level pre-filtering
- **Clean terminal alerts** using Rich
- **Includes test suite** for the detection engine

---

## Tech Stack

- **Python 3**
- **Scapy** (packet capture and networking layers)
- **Rich** (CLI formatting and presentation)

---

## Installation

```bash
git clone https://github.com/praneeth3696/NetSpecter.git
cd NetSpecter
pip install -r requirements.txt
```

---

## Requirements

- **Linux** (Ubuntu / Kali recommended)
- **Root privileges** (`sudo`) required for raw socket access
- **libpcap** installed

Install libpcap if needed (Ubuntu/Debian):
```bash
sudo apt install libpcap-dev
```

---

## Usage

Start scanning on the auto-detected default interface:
```bash
sudo python3 main.py scan
```

Optional (specify an interface):
```bash
sudo python3 main.py scan --iface eth0
```

---

## Demo

Run this command in another terminal while NetSpecter is scanning to simulate an insecure login:

```bash
curl -X POST http://testphp.vulnweb.com/login.php -d "username=admin&password=1234"
```

### Example Output

```text
⚠️ INSECURE CREDENTIAL TRANSMISSION DETECTED

Source IP: 127.0.0.1
Destination IP: 127.0.0.1
Detection Type: form

Username: admin
Password: 1234
Confidence: HIGH

Credentials are transmitted in plaintext and can be intercepted.
```

---

## Limitations

- Does **NOT** work on HTTPS (encrypted traffic).
- Does **NOT** perform full TCP stream reassembly (split-packet payloads may be missed).
- Limited support for compressed bodies (`gzip`, `br`) or HTTP/2 traffic frames.

---

## Project Structure

```
NetSpecter/
├── detectors/
│   ├── __init__.py
│   └── http_credential_detector.py
│
├── tests/
│   └── test_http_credential_detector.py
│
├── docs/
│   └── http_credential_module_audit.md
│
├── main.py
├── sniffer.py
├── detector_wrapper.py
├── formatter.py
│
├── requirements.txt
├── .gitignore
└── README.md
```

---

## Use Cases

- Demonstrating the fundamental insecurity of HTTP vs HTTPS.
- Learning packet inspection, sniffing, and network protocols.
- Educational cybersecurity experiments.
- Debugging insecure legacy API implementations.

---

## Disclaimer

> **Warning**
> This tool is intended for educational and authorized testing purposes only. 
> Do **NOT** use this tool on networks or systems without proper authorization and permission.

---

## Author

**Praneeth**
