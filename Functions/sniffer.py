#!/usr/bin/env python3

from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, sniff, wrpcap
import csv
import sys
from collections import Counter

def analyze_pcap(pcap_file):
    packets = rdpcap(pcap_file)

    protocol_count = Counter()
    ip_count = Counter()
    port_count = Counter()
    dns_queries = []

    for pkt in packets:
        # Count protocols
        if pkt.haslayer(TCP):
            protocol_count['TCP'] += 1
            port_count[pkt[TCP].dport] += 1
        elif pkt.haslayer(UDP):
            protocol_count['UDP'] += 1
            port_count[pkt[UDP].dport] += 1
        elif pkt.haslayer(ICMP):
            protocol_count['ICMP'] += 1
        elif pkt.haslayer(ARP):
            protocol_count['ARP'] += 1

        # Count IPs
        if pkt.haslayer(IP):
            ip_count[pkt[IP].src] += 1
            ip_count[pkt[IP].dst] += 1

        # DNS queries
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            query = pkt[DNSQR].qname.decode('utf-8', errors='ignore')
            dns_queries.append(query)


    # Save to CSV files
    save_protocols_csv(protocol_count, 'protocols.csv')
    save_ips_csv(ip_count, 'top_ips.csv')
    save_ports_csv(port_count, 'top_ports.csv')

    if dns_queries:
        save_dns_csv(dns_queries, 'dns_queries.csv')


def get_service(port):
    services = {
        20: 'FTP-DATA', 21: 'FTP', 22: 'SSH',
        25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
        143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 3389: 'RDP',
        5353: 'mDNS', 8080: 'HTTP-ALT', 1900: 'SSDP'
    }
    return services.get(port, 'Unknown')

def save_protocols_csv(protocol_count, filename):
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Protocol', 'Count'])
        for proto, count in protocol_count.most_common():
            writer.writerow([proto, count])

def save_ips_csv(ip_count, filename):
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['IP Address', 'Packet Count'])
        for ip, count in ip_count.most_common(20):  # Top 20
            writer.writerow([ip, count])

def save_ports_csv(port_count, filename):
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Port', 'Service', 'Count'])
        for port, count in port_count.most_common(20):  # Top 20
            service = get_service(port)
            writer.writerow([port, service, count])

def save_dns_csv(dns_queries, filename):
    # Count unique queries
    query_count = Counter(dns_queries)

    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Domain', 'Query Count'])
        for query, count in query_count.most_common():
            writer.writerow([query, count])

def sniffer(pcapname, time=10):
    capture = sniff(timeout=time)
    wrpcap(pcapname, capture)

def filter_packets(pcap_file, protocol):

    packets = rdpcap(pcap_file)
    filtered = []

    for pkt in packets:
        if protocol.lower() == 'tcp' and pkt.haslayer(TCP):
            filtered.append(pkt)
        elif protocol.lower() == 'udp' and pkt.haslayer(UDP):
            filtered.append(pkt)
        elif protocol.lower() == 'icmp' and pkt.haslayer(ICMP):
            filtered.append(pkt)
        elif protocol.lower() == 'arp' and pkt.haslayer(ARP):
            filtered.append(pkt)
        elif protocol.lower() == 'dns' and pkt.haslayer(DNS):
            filtered.append(pkt)
        elif protocol.lower() == 'http':
            if pkt.haslayer(TCP) and (pkt[TCP].dport == 80 or pkt[TCP].sport == 80):
                filtered.append(pkt)
        elif protocol.lower() == 'https':
            if pkt.haslayer(TCP) and (pkt[TCP].dport == 443 or pkt[TCP].sport == 443):
                filtered.append(pkt)


    if filtered:
        output = f"{protocol}_filtered.pcap"
        wrpcap(output, filtered)

    return filtered

def filter_mitm_traffic(pcap_file, target_ip):
    """Filter PCAP to only show traffic from/to a specific target IP (for MITM captures)"""
    print(f"Filtering MITM traffic for target: {target_ip}")
    packets = rdpcap(pcap_file)
    print(f"Total packets before filtering: {len(packets)}")
    
    # Filter to only packets involving the target device
    filtered_packets = [pkt for pkt in packets if pkt.haslayer(IP) and 
                       (pkt[IP].src == target_ip or pkt[IP].dst == target_ip)]
    
    print(f"Packets after MITM filtering: {len(filtered_packets)}")
    
    unique_ips = set()
    for pkt in filtered_packets:
        if pkt.haslayer(IP):
            unique_ips.add(pkt[IP].src)
            unique_ips.add(pkt[IP].dst)
    
    print(f"Target device ({target_ip}) communicated with IPs: {sorted(unique_ips)}")
    
    # Overwrite the original file with filtered packets
    wrpcap(pcap_file, filtered_packets)
    print(f"✓ Saved {len(filtered_packets)} filtered packets back to {pcap_file}")
    
    return len(filtered_packets)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("starting new capture")
        sniffer("output.pcap")
    else:
        print("loading pcap from memory")
        analyze_pcap("output.pcap")
        filter_packets("output.pcap", "http")
