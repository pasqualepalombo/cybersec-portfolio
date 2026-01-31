# Port Scanner

A lightweight Python port scanner for network reconnaissance and security testing.

## Features

- Scans common network ports (FTP, SSH, HTTP, HTTPS, MySQL, RDP, etc.)
- Banner grabbing for service identification
- Configurable timeout settings
- Clean, readable output

## Usage

```bash
python3 port_scanner.py
```

Enter a target IP address or hostname when prompted (default: localhost).

## Example Output

```
--------------------------------------------------
Scanning Target: 192.168.1.1
Time started: 2025-01-31 14:30:00.123456
--------------------------------------------------
[+] Port 22 is OPEN
[+] Port 80 is OPEN
    Banner: HTTP/1.1 400 Bad Request...
[+] Port 443 is OPEN
--------------------------------------------------
Scan completed. Found 3 open ports
Time finished: 2025-01-31 14:30:15.789012
--------------------------------------------------
```

## Requirements

- Python 3.x
- No external dependencies

## Legal Notice

⚠️ **Use responsibly and ethically.** Only scan networks and systems you own or have explicit permission to test.

## Author

Pasquale Palombo

## License

MIT