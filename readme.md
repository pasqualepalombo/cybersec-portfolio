# Cybersecurity Tools Suite 🛡️

A collection of Python-based security tools for network reconnaissance, penetration testing, and cryptographic operations. Developed as part of a comprehensive cybersecurity learning path.

## 📋 Table of Contents

- [Overview](#overview)
- [Tools Included](#tools-included)
- [Requirements](#requirements)
- [Usage](#usage)
  - [Port Scanner](#1-port-scanner)
  - [Packet Sniffer](#2-packet-sniffer)
  - [Crypto Tools Suite](#3-crypto-tools-suite)
  - [SSL Certificate Checker](#4-ssl-certificate-checker)
- [Legal Notice](#legal-notice)
- [Author](#author)
- [License](#license)

## 🔍 Overview

This repository contains a suite of cybersecurity tools built with Python for educational and authorized security testing purposes. Each tool focuses on a specific aspect of network security, cryptography, or system reconnaissance.

## 🛠️ Tools Included

### 1. **Port Scanner** (`port_scanner.py`)
A lightweight network port scanner for discovering open ports and identifying running services.

### 2. **Packet Sniffer** (`packet_sniffer.py`)
Real-time network traffic analyzer with protocol dissection capabilities.

### 3. **Crypto Tools Suite** (`crypto_tools.py`)
Multi-purpose cryptographic toolkit including hash cracking and file encryption/decryption.

### 4. **SSL Certificate Checker** (`ssl_checker.py`)
SSL/TLS certificate validation and security assessment tool.

## 📦 Requirements

### Python Version
- Python 3.7 or higher

### Dependencies

```bash
# Core dependencies
pip install scapy
pip install cryptography
pip install colorama

# For Windows users (Packet Sniffer)
# Install Npcap: https://npcap.com/#download
```

### System Requirements
- **Linux/macOS**: Most tools work out of the box
- **Windows**: Requires Npcap for packet capture functionality
- **Permissions**: Some tools require administrator/root privileges


## 📖 Usage

### 1. Port Scanner

Scans common network ports on a target host and attempts service identification through banner grabbing.

```bash
python3 port_scanner.py
```

**Interactive prompts:**
- Enter target IP/hostname (default: localhost)
- Scans common ports: 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443

**Example output:**
```
--------------------------------------------------
Scanning Target: 192.168.1.1
Time started: 2026-02-14 10:30:00.123456
--------------------------------------------------
[+] Port 22 is OPEN
[+] Port 80 is OPEN
    Banner: HTTP/1.1 400 Bad Request...
[+] Port 443 is OPEN
--------------------------------------------------
Scan completed. Found 3 open ports
Time finished: 2026-02-14 10:30:15.789012
--------------------------------------------------
```

**Features:**
- Fast TCP connection scanning
- Service banner grabbing
- Configurable timeout settings
- Clean, timestamped output

---

### 2. Packet Sniffer

Captures and analyzes network packets in real-time with protocol-specific dissection.

```bash
# Requires administrator/root privileges
sudo python3 packet_sniffer.py
```

**BPF Filter Examples:**
```
tcp port 80        # HTTP traffic
tcp port 443       # HTTPS traffic
udp port 53        # DNS queries
host 192.168.1.1   # Specific IP address
tcp or udp         # All TCP/UDP traffic (default)
```

**Example output:**
```
[+] New Packet: 192.168.1.100 -> 93.184.216.34
    Protocol: TCP | Port 54321 -> 80 | Flags: PA
    Payload: GET / HTTP/1.1
Host: example.com...
```

**Features:**
- Real-time packet capture
- TCP/UDP/ICMP protocol support
- Payload extraction and display
- BPF filtering for targeted capture
- Windows/Linux/macOS compatible

---

### 3. Crypto Tools Suite

Multi-functional cryptographic toolkit with an interactive menu system.

```bash
python3 crypto_tools.py
```

**Available Tools:**

#### 3.1 Hash Password
Generate cryptographic hashes for passwords.

```
Supported algorithms: md5, sha1, sha256, sha512
```

#### 3.2 Crack Password Hash
Dictionary-based hash cracking tool.

```
Requirements:
- Target hash
- Wordlist file (e.g., rockyou.txt)
- Hash algorithm
```

**Example:**
```
[*] Starting hash crack...
[*] Target hash: 5f4dcc3b5aa765d61d8327deb882cf99
[*] Algorithm: md5
[*] Wordlist: rockyou.txt

[✓] PASSWORD FOUND!
[✓] Password: password
[✓] Attempts: 2
```

#### 3.3 Generate Encryption Key
Creates a Fernet encryption key saved to `encryption.key`.

#### 3.4 Encrypt File
Encrypts files using Fernet symmetric encryption.

```
Input: myfile.txt
Output: myfile.txt.encrypted
```

#### 3.5 Decrypt File
Decrypts previously encrypted files.

```
Input: myfile.txt.encrypted
Output: myfile.txt
```

**Features:**
- Multiple hashing algorithms (MD5, SHA-1, SHA-256, SHA-512)
- Dictionary-based hash cracking
- Fernet symmetric encryption
- Secure key management
- Progress tracking for long operations
- Color-coded output for clarity

---

### 4. SSL Certificate Checker

Validates SSL/TLS certificates and checks for security issues.

```bash
python3 ssl_checker.py
```

**Features:**
- Certificate expiration validation
- Issuer information extraction
- Common name verification
- Security best practices checking

---


**⚠️ IMPORTANT - READ CAREFULLY**

These tools are provided for **educational purposes** and **authorized security testing only**.

### ✅ Acceptable Use:
- Testing your own systems and networks
- Authorized penetration testing with written permission
- Educational learning in controlled lab environments
- Security research on systems you own

### ❌ Prohibited Use:
- Unauthorized access to any computer system
- Network scanning without explicit permission
- Any activity that violates local, state, or federal laws
- Malicious intent or illegal activities

## 👨‍💻 Author

**Pasquale Palombo**

- 🎓 Background: Computer Engineering + Cybersecurity Master's
- 💼 Experience: Full-Stack Developer transitioning to Cybersecurity


## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
