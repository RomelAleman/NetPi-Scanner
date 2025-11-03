"""
- Nmap scanner implementation
- Scans specified network ranges for connected devices (defaults to .config specified ip and subnet if not provided)
- Stores found devices including their IP, MAC, and hostname (if available) in a CSV file
"""

import nmap, csv
import argparse

config = {}

def setup_config():
    # loop through each line in .config
    with open('.config') as f:
        lines = f.readlines()
        for line in lines:
            line = line.strip()
            # ignore empty lines and comments
            if not line or line.startswith('#'):
                continue
            # ignore malformed lines without '='
            if '=' not in line:
                continue
            key, value = line.split('=', 1)
            config[key.strip()] = value.strip()

def scan_network(addr, dns_addr, subnet='24'):
    nm = nmap.PortScanner()

    addr = f"{addr}/{subnet}"
    
    nm.scan(hosts=addr, arguments='-sn')  # Ping scan

    print (f"Scanning network: {addr}")

    devices = []
    for host in nm.all_hosts():
        ip = host
        mac = nm[host]['addresses'].get('mac', 'N/A')
        hostname = nm[host]['hostnames'][0]['name'] if nm[host]['hostnames'] else 'N/A'
        active = nm[host].state() == 'up'

        devices.append({'IP': ip, 'MAC': mac, 'Hostname': hostname, 'Active': active})

    return devices

def save_to_csv(devices, filename='devices.csv'):
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['IP', 'MAC', 'Hostname', 'Active']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for device in devices:
            writer.writerow(device)

def update_config():
    for key, value in config.items():
        if key == 'address':
            print(f"Address ({value}): ")
            config['address'] = input() or value
        elif key == 'subnet':
            print(f"Subnet ({value}): ")
            config['subnet'] = input() or value
        elif key == 'dns':
            print(f"DNS Server ({value}): ")
            config['dns'] = input() or value
    with open('.config', 'w') as f:
        for key, value in config.items():
            f.write(f"{key}={value}\n")

def main():

    # parse command line arguments
    parser = argparse.ArgumentParser(description='Nmap Network Scanner')
    parser.add_argument('-u', '--update-config', action='store_true', help='Update .config file')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug mode')
    args = parser.parse_args()

    if args.update_config:
        update_config()
        print(".config file updated.")

    if args.debug:
        print("Debug mode enabled")


    """
    setup_config()
    addr = config.get('address', '<address>')
    dns_addr = config.get('dns', '<dns_server>')

    devices = scan_network(addr, dns_addr, config.get('subnet', '24')) 

    save_to_csv(devices)
    """

if __name__ == "__main__":
    main()