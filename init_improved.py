#!/usr/bin/env python3

"""
- Pulls scripts from init_config.py and host.py after installing required packages
- Runs package installation function
"""

import subprocess
from Functions.init_config import config_initialization
from WebUI.host import begin_web_ui

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

if __name__ == "__main__":
    package_installation()
    config_initialization()
    begin_web_ui()