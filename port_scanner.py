#!/usr/bin/env python3

"""
Simple Port Scanner
Author: Pasquale Palombo
Description: Scans common ports on a target host
"""

import socket
import sys
from datetime import datetime
from colorama import Fore, Style, init

# Inizializza colorama per Windows
init(autoreset=True)

def scan_port(target, port, timeout=1):
    """
    Scans a single port on target host
    Returns: True if port is open, False otherwise
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        return result == 0
    except socket.gaierror:
        print(f"{Fore.RED}Hostname {target} could not be resolved")
        sys.exit()
    except socket.error:
        print(f"{Fore.RED}Could not connect to {target}")
        sys.exit()

def banner_grab(target, port, timeout=2):
    """
    Attempts to grab banner from open port
    Returns: Banner string or None
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        return banner
    except:
        return None

def save_results(target, open_ports, scan_info, filename="scan_results.txt"):
    """
    Saves scan results to file
    Args:
        target: Target IP/hostname
        open_ports: List of dictionaries with port info
        scan_info: Dictionary with scan metadata
        filename: Output filename
    """
    try:
        with open(filename, "w") as f:
            f.write("=" * 60 + "\n")
            f.write("           PORT SCANNER RESULTS\n")
            f.write("=" * 60 + "\n")
            f.write(f"Target: {target}\n")
            f.write(f"Scan Date: {scan_info['start_time']}\n")
            f.write(f"Port Range: {scan_info['start_port']}-{scan_info['end_port']}\n")
            f.write(f"Duration: {scan_info['duration']}\n")
            f.write("=" * 60 + "\n\n")
            
            f.write(f"Total Open Ports: {len(open_ports)}\n")
            f.write("-" * 60 + "\n\n")
            
            if open_ports:
                for port_info in open_ports:
                    f.write(f"Port {port_info['port']}: OPEN\n")
                    if port_info.get('banner'):
                        f.write(f"  Banner: {port_info['banner'][:100]}\n")
                    f.write("\n")
            else:
                f.write("No open ports found.\n")
            
            f.write("\n" + "=" * 60 + "\n")
            f.write("End of Report\n")
            f.write("=" * 60 + "\n")
        
        print(f"\n{Fore.GREEN}[✓] Results saved to {filename}")
        return True
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error saving results: {e}")
        return False

def main():
    print(f"{Fore.CYAN}{'=' * 60}")
    print(f"{Fore.CYAN}           ENHANCED PORT SCANNER")
    print(f"{Fore.CYAN}{'=' * 60}\n")
    
    # Target configuration
    target = input("Enter target IP/hostname (or press Enter for localhost): ").strip()
    if not target:
        target = "127.0.0.1"
    
    # Feature 3: Scan range customizzabile
    print(f"\n{Fore.YELLOW}[?] Port Range Configuration")
    start_port_input = input("    Start port (default 1): ").strip()
    end_port_input = input("    End port (default 1000): ").strip()
    
    start_port = int(start_port_input) if start_port_input else 1
    end_port = int(end_port_input) if end_port_input else 1000
    
    # Validazione range
    if start_port < 1 or end_port > 65535 or start_port > end_port:
        print(f"{Fore.RED}[!] Invalid port range! Must be 1-65535 and start <= end")
        sys.exit(1)
    
    # Opzione salvataggio
    save_to_file = input(f"\n{Fore.YELLOW}[?] Save results to file? (y/n, default n): ").strip().lower()
    filename = "scan_results.txt"
    if save_to_file == 'y':
        custom_filename = input("    Filename (default scan_results.txt): ").strip()
        if custom_filename:
            filename = custom_filename
    
    # Inizio scan
    start_time = datetime.now()
    print(f"\n{Fore.CYAN}{'-' * 60}")
    print(f"{Fore.CYAN}Scanning Target: {Fore.WHITE}{target}")
    print(f"{Fore.CYAN}Port Range: {Fore.WHITE}{start_port}-{end_port}")
    print(f"{Fore.CYAN}Time started: {Fore.WHITE}{start_time}")
    print(f"{Fore.CYAN}{'-' * 60}\n")
    
    open_ports = []
    total_ports = end_port - start_port + 1
    scanned = 0
    
    # Scan ports
    for port in range(start_port, end_port + 1):
        scanned += 1
        
        # Progress indicator ogni 100 porte
        if scanned % 100 == 0:
            progress = (scanned / total_ports) * 100
            print(f"{Fore.YELLOW}[*] Progress: {scanned}/{total_ports} ({progress:.1f}%)", end='\r')
        
        if scan_port(target, port):
            port_info = {'port': port}
            
            # Feature 2: Colora output
            print(f"{Fore.GREEN}[+] Port {port:5d} is OPEN", end='')
            
            # Try to grab banner
            banner = banner_grab(target, port)
            if banner:
                port_info['banner'] = banner
                print(f" - Banner: {Fore.CYAN}{banner[:60]}...", end='')
            
            print()  # Newline
            open_ports.append(port_info)
    
    # Fine scan
    end_time = datetime.now()
    duration = end_time - start_time
    
    print(f"\n{Fore.CYAN}{'-' * 60}")
    print(f"{Fore.GREEN}[✓] Scan completed!")
    print(f"{Fore.CYAN}Found {Fore.WHITE}{len(open_ports)}{Fore.CYAN} open ports out of {Fore.WHITE}{total_ports}{Fore.CYAN} scanned")
    print(f"{Fore.CYAN}Duration: {Fore.WHITE}{duration}")
    print(f"{Fore.CYAN}Time finished: {Fore.WHITE}{end_time}")
    print(f"{Fore.CYAN}{'-' * 60}\n")
    
    # Stampa riepilogo porte aperte
    if open_ports:
        print(f"{Fore.YELLOW}Open Ports Summary:")
        for port_info in open_ports:
            print(f"  {Fore.GREEN}• Port {port_info['port']}")
    
    # Feature 1: Salva risultati in file
    if save_to_file == 'y':
        scan_info = {
            'start_time': start_time,
            'end_time': end_time,
            'duration': duration,
            'start_port': start_port,
            'end_port': end_port
        }
        save_results(target, open_ports, scan_info, filename)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Scan interrupted by user")
        print(f"{Fore.CYAN}Exiting...")
        sys.exit(0)