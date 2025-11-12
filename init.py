#!/usr/bin/env python3

"""
- Installation script for NetPi-Scanner
- Installs dependencies and sets up initial configuration
"""

import subprocess, re
import WebUI.host
import socket

# subprocess call to install required packages
def package_installation():
    
    # We can add more packages here as needed
    packages_to_install = ['python3-nmap', 
                           'python3-scapy', 
                           'python3-flask']
    
    for pkg in packages_to_install:
        print(f"\nInstalling {pkg}...")
        subprocess.check_call(['sudo', 'apt', 'install', '-y', pkg])
        print()

# Initial configuration for user to add there adresses and subnet
# Defaults to most common home network configurations if not provided
def config_initialization():

    # Find current ip address for finding default router
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("1.1.1.1", 80))
    ip = s.getsockname()[0]
    s.close()
    
    print("\nWelcome to NetPi-Scanner setup!")
    print("-------------------------------\n")

    entry_list= [
        "router",
        "subnet",
        "dns"
    ]

    # default values
    defaults = [
        '.'.join(ip.split('.')[:-1]) + '.1',  # default router based on current ip
        '24',
        '.'.join(ip.split('.')[:-1]) + '.1'   # default dns based on current ip
    ]

    # configuration prompts
    configurations = [
        f"IPV4 router address ({defaults[0]}): ",
        "desired subnet (24): ",
        f"IPV4 router dns ({defaults[2]}): "
    ]

    # open file for writing configurations to config file
    # uses regex to check if input is valid
    # if nothing provided, use default values
    # we can add more configurations if needed
    with open('.config', 'w') as f:
        
        for i, config in enumerate(configurations):
            user_input = input(f"Please enter the {config}")
            if not user_input:
                user_input = defaults[i]
            elif user_input and (i == 0 or i == 2):
                # regex validation for IP address
                ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
                if not ip_pattern.match(user_input):
                    print("\nInvalid IP address format. Using default.")
                    user_input = defaults[i]
            elif user_input and i == 1:
                # validation for subnet
                if not user_input.isdigit() or not (0 < int(user_input) <= 32):
                    print("\nInvalid subnet format. Using default.")
            key = entry_list[i]
            f.write(f"{key}={user_input}\n")
            print() # new line

        print("Configuration saved to .config file.")
    return

if __name__ == "__main__":
    package_installation()
    config_initialization()
    WebUI.host.begin_web_ui()