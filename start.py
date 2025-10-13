from scapy.all import *

addr = "192.168.1.1/24" #put own router address and subnet
dns_addr = "192.168.1.1"   

# ARP packet to ping active active devices 
p = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=addr)
answered, _ = srp(p, timeout=1, verbose=False)

for _, rcv in answered:
    ip = rcv.psrc # return source ip
    mac = rcv.hwsrc # returns mac addr
    print(f"IP: {ip}, MAC: {mac}")

    # build reverse-DNS name for look up
    rev = ".".join(ip.split(".")[::-1]) + ".in-addr.arpa"

    # send PTR query to your DNS server
    query = IP(dst=dns_addr) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=rev, qtype="PTR"))
    resp = sr1(query, timeout=1, verbose=False)

    if resp and resp.haslayer(DNS) and resp[DNS].ancount > 0:
        for i in range(resp[DNS].ancount):
            rr = resp[DNS].an[i]
            name = rr.rdata.decode() if isinstance(rr.rdata, bytes) else rr.rdata
            print("Hostname:", name)
    else:
        print("No DNS entry found")

    print()







