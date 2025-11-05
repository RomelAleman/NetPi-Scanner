from scapy.all import *

addr = "" 
dns_addr = "" 

with open(".config") as f:
    for raw in f:
        line = raw.strip()
        # Skip empty lines and comments
        if not line or line.startswith("#"):
            continue
        # Only process lines with a key=value format
        if "=" not in line:
            continue
        key, value = [x.strip() for x in line.split("=", 1)]
        # Drop inline comments after the value, if any
        if "#" in value:
            value = value.split("#", 1)[0].strip()
        if key == "address":
            addr = value
        elif key == "subnet":
            addr += "/" + value
        elif key == "dns":
            dns_addr = value

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







