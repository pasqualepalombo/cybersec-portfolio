#python3

"""
Simple Port Scanner
Author: Pasquale Palombo
Description: Scans common ports on a target host
"""

import socket
import sys
from datetime import datetime


def scan_port(target, port, timeout = 1):
    """
    Scan a single port on target host
    Returns: True if port is open, false otherwise
    """
    try:
        # TCP socket creation
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # Try connection
        result = sock.connect_ex((target, port))
        sock.close()

        # connect_ex is 0 if true
        return result == 0
    
    except socket.gaierror:
        print(f"Hostname {target} could not be resolved")
        sys.exit()
    except socket.error:
        print(f"Could not connect to {target}")


def banner_grab(target, port, timeout = 2):
    """
    Attempts to grab banner (response message) from open port
    Returs: Banner string or None
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))

        # Generic request
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")

        # Response
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        return banner

    except:
        return None


def main():
    # Target Configuration
    target = input("Enter target IP/hostname (or press ENTER for localhost)")
    if not target:
        target = "127.0.0.1"
    
    # Common ports
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443]

    print("-" * 50)
    print(f"Scanning Target: {target}")
    print(f"Time started: {datetime.now()}")
    print("-" * 50)

    open_ports = []

    # Scan ports
    for port in common_ports:
        if scan_port(target, port):
            open_ports.append(port)
            print(f"[+] Port {port} is OPEN")

            # Banner grabbing
            banner = banner_grab(target, port)
            if banner:
                (f"    Banner: {banner[:100]}")
            else:
                print(f"[-] Port {port} is closed")
    
    print("-" * 50)
    print(f"Scan completed. Found {len(open_ports)} open ports")
    print(f"Time finished: {datetime.now()}")
    print("-" * 50)


if __name__ == "__main__":
    main()