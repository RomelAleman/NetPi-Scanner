#!/usr/bin/env python3

"""
- Nmap scanner implementation
- Scans specified network ranges for connected devices (defaults to .config specified ip and subnet if not provided)
- Stores found devices including their IP, MAC, and hostname (if available) into a file for later reference
"""

import nmap, os, csv
import argparse

config = {}

def setup_config():
    # loop through each line in .config
    with open('.config') as f:
        lines = f.readlines()
        for line in lines:
            line = line.strip()
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

"""def save_to_csv(devices, filename='devices.csv'):
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['IP', 'MAC', 'Hostname', 'Active']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for device in devices:
            writer.writerow(device)"""

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
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Nmap Network Scanner')
    
    parser.add_argument('-u', 
                        '--update-config', 
                        action='store_true',  # Use store_true for boolean flags
                        help='Update .config file')
    parser.add_argument('-v',
                        '--verbose',
                        action='store_true',  # Use store_true for boolean flags
                        help='Enable verbose mode')
    parser.add_argument('-s',
                        '--scan',
                        action='store_true',  # Use store_true for boolean flags
                        help='Scan the network')
    args = parser.parse_args()

    if args.update_config:
        update_config()
        print(".config file updated.")

    if args.scan:
        setup_config()
        addr = config.get('address', '<address>')
        dns_addr = config.get('dns', '<dns_server>')

        devices = scan_network(addr, dns_addr, config.get('subnet', '24'))

        save_devices(devices)

    if args.verbose:
        print("Verbose mode is enabled.")


    """
    setup_config()
    addr = config.get('address', '<address>')
    dns_addr = config.get('dns', '<dns_server>')

    devices = scan_network(addr, dns_addr, config.get('subnet', '24')) 

    save_to_csv(devices)
    """

if __name__ == "__main__":
    main()