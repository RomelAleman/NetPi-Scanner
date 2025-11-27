#!/usr/bin/env python3

"""
- Nmap scanner implementation
- Scans specified network ranges for connected devices (defaults to .config specified ip and subnet if not provided)
- Stores found devices including their IP, MAC, and hostname (if available) into a file for later reference
"""
import logging
import nmap, os, csv, socket
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, sr1

config = {}
log_file_path = 'scheduled_logs/scan.log' # log location
os.makedirs(os.path.dirname(log_file_path), exist_ok=True) #double check that it's there
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler(log_file_path),
        logging.StreamHandler()  # optional: also log to console
    ]
    )

def setup_config():
    # loop through each line in .config
    with open('.config') as f:
        lines = f.readlines()
        for line in lines:
            line = line.strip()
            key, value = line.split('=', 1)
            config[key.strip()] = value.strip()
    # normalize older key name `router` to the canonical `address`
    if 'router' in config and 'address' not in config:
        config['address'] = config['router']

def scan_network(addr, dns_addr, subnet='24'):
    nm = nmap.PortScanner()

    addr = f"{addr}/{subnet}"
    
    nm.scan(hosts=addr, arguments='-sn')  # Ping scan

    print (f"Scanning network: {addr}")

    devices = []
    for host in nm.all_hosts():
        ip = host
        mac = nm[host]['addresses'].get('mac', 'N/A')
        # prefer nmap-discovered hostname, fall back to reverse DNS (PTR) lookup
        hostname = get_hostname(ip, dns_addr)
        if not hostname:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = 'N/A'
        active = nm[host].state() == 'up'

        devices.append({'IP': ip, 'MAC': mac, 'Hostname': hostname, 'Active': active})

    return devices

def get_hostname(ip, dns_addr=None):
 
    if not dns_addr:
        dns_addr = '1.1.1.1'

    parts = ip.split('.')
    if len(parts) != 4:
        return None

    rev = ".".join(parts[::-1]) + ".in-addr.arpa"

    try:
        query = IP(dst=dns_addr) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=rev, qtype='PTR'))
        resp = sr1(query, timeout=1, verbose=False)
        if not resp or not resp.haslayer(DNS) or resp[DNS].ancount == 0:
            return None

        ans = resp[DNS].an
        # scapy returns first answer in ans; extract rdata
        rdata = getattr(ans, 'rdata', None)
        if rdata is None:
            return None
        if isinstance(rdata, bytes):
            try:
                rdata = rdata.decode()
            except Exception:
                rdata = None
        if isinstance(rdata, str):
            return rdata.rstrip('.')

    except Exception:
        return None

    return None

def load_devices(filename='CSV/saved_devices.csv'):
    devices = []
    if os.path.exists(filename):
        with open(filename, 'r', newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                devices.append(row)
    return devices

def save_devices(new_devices, filename='CSV/saved_devices.csv'):
    # Load existing devices
    existing_devices = load_devices(filename)

    # Create a dictionary for easy lookup
    device_dict = {device['MAC']: device for device in existing_devices}

    # Update existing devices and add new ones
    for device in new_devices:
        mac = device['MAC']
        if mac in device_dict:
            # Update existing device
            device_dict[mac].update(device)  # Update existing attributes
        else:
            # Add new device
            device_dict[mac] = device

    # Ensure CSV directory exists, then write updated device list back to file
    dirname = os.path.dirname(filename)
    if dirname and not os.path.exists(dirname):
        os.makedirs(dirname, exist_ok=True)

    with open(filename, 'w', newline='') as f:
        fieldnames = ['IP', 'MAC', 'Hostname', 'Active']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(device_dict.values())

def update_config():
    # Make prompts/validation match init.py's behavior (router, subnet, dns)
    entry_list = [
        "router",
        "subnet",
        "dns"
    ]

    defaults = [
        "192.168.0.1",
        "24",
        "192.168.0.1"
    ]

    configurations = [
        "IPV4 router address (192.168.0.1): ",
        "desired subnet (24): ",
        "IPV4 router dns (192.168.0.1): "
    ]

    # Use existing values as defaults when present
    existing = {
        'router': config.get('router') or config.get('address'),
        'subnet': config.get('subnet'),
        'dns': config.get('dns')
    }

    # Write updated config using same validation as init.py
    with open('.config', 'w') as f:
        for i, prompt in enumerate(configurations):
            current = existing.get(entry_list[i]) or defaults[i]
            user_input = input(f"Please enter the {prompt}")
            if not user_input:
                user_input = current
            elif user_input and (i == 0 or i == 2):
                # regex validation for IP address
                import re
                ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
                if not ip_pattern.match(user_input):
                    print("\nInvalid IP address format. Using default.")
                    user_input = defaults[i]
            elif user_input and i == 1:
                # validation for subnet
                if not user_input.isdigit() or not (0 < int(user_input) <= 32):
                    print("\nInvalid subnet format. Using default.")
                    user_input = defaults[i]

            key = entry_list[i]
            config[key] = user_input
            f.write(f"{key}={user_input}\n")

    # keep canonical 'address' key for compatibility
    if 'router' in config:
        config['address'] = config['router']

def device_log(new_devices,filename='CSV/saved_devices.csv'):
    logger = logging.getLogger(__name__)
    existing_devices = load_devices(filename)
    # Create a dictionary for easy lookup
    device_dict = {device['MAC']: device for device in existing_devices}

    # Update existing devices and add new ones
    for device in new_devices:
        mac = device['MAC']
        if mac in device_dict:
            # Update existing device
            device_dict[mac].update(device)  # Update existing attributes
            logger.info(f"Update existing device {mac}")
        else:
            # Add new device
            device_dict[mac] = device    
            logger.info(f"Add new device {mac}")

    #same as save_devices()
    # Ensure CSV directory exists, then write updated device list back to file
    dirname = os.path.dirname(filename)
    if dirname and not os.path.exists(dirname):
        os.makedirs(dirname, exist_ok=True)

    with open(filename, 'w', newline='') as f:
        fieldnames = ['IP', 'MAC', 'Hostname', 'Active']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(device_dict.values())