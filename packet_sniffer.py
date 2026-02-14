#!/usr/bin/env python3
"""
Basic Packet Sniffer - Windows Compatible
Captures and displays network packets
"""

from scapy.all import sniff, IP, TCP, UDP, Raw, Ether
import sys

def packet_callback(packet):
    """
    Callback function for each captured packet
    """
    try:
        # Check se ha layer IP
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            
            print(f"\n[+] New Packet: {ip_src} -> {ip_dst}")
            
            # TCP packet
            if TCP in packet:
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                flags = packet[TCP].flags
                print(f"    Protocol: TCP | Port {sport} -> {dport} | Flags: {flags}")
                
                # Mostra payload se presente
                if Raw in packet:
                    try:
                        payload = packet[Raw].load
                        # Decodifica solo se printable
                        payload_str = payload.decode('utf-8', errors='ignore')
                        if payload_str.isprintable() or any(c in payload_str for c in ['\n', '\r', '\t']):
                            print(f"    Payload: {payload_str[:100]}...")
                        else:
                            print(f"    Payload: [Binary Data - {len(payload)} bytes]")
                    except Exception as e:
                        print(f"    Payload: [Error decoding: {e}]")
            
            # UDP packet
            elif UDP in packet:
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                print(f"    Protocol: UDP | Port {sport} -> {dport}")
                
                if Raw in packet:
                    payload = packet[Raw].load
                    print(f"    Payload: [UDP Data - {len(payload)} bytes]")
            
            else:
                # Altri protocolli IP
                proto = packet[IP].proto
                proto_names = {1: "ICMP", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE"}
                proto_name = proto_names.get(proto, f"Unknown({proto})")
                print(f"    Protocol: {proto_name}")
                
    except Exception as e:
        # Cattura errori senza crashare
        print(f"[!] Error processing packet: {e}")

def main():
    print("=" * 60)
    print("    Packet Sniffer - Windows Compatible")
    print("    Press Ctrl+C to stop")
    print("=" * 60)
    
    # Chiedi filtro
    print("\nCommon filters:")
    print("  - tcp port 80       (HTTP traffic)")
    print("  - tcp port 443      (HTTPS traffic)")
    print("  - udp port 53       (DNS traffic)")
    print("  - host 192.168.1.1  (specific IP)")
    print("  - tcp or udp        (all TCP/UDP)")
    
    filter_str = input("\nEnter BPF filter (or press Enter for 'tcp or udp'): ").strip()
    if not filter_str:
        filter_str = "tcp or udp"
    
    print(f"\n[*] Starting capture with filter: '{filter_str}'")
    print("[*] Press Ctrl+C to stop\n")
    print("-" * 60)
    
    try:
        # Sniff con error handling migliorato
        sniff(
            filter=filter_str, 
            prn=packet_callback, 
            store=False,
            # Specifica l'interfaccia se necessario (opzionale)
            # iface="Ethernet"  # Decommentare e modificare se serve
        )
    except PermissionError:
        print("\n[!] Error: Need administrator privileges!")
        print("[!] Close VS Code and reopen as Administrator")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n" + "=" * 60)
        print("[*] Capture stopped by user")
        print("=" * 60)
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        print("[!] Try running as Administrator or check Npcap installation")

if __name__ == "__main__":
    main()