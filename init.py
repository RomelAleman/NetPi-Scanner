#!/usr/bin/env python3

"""
- Pulls scripts from init_config.py and host.py after installing required packages
- Runs package installation function
- Can add cron jobs functions, but just wasn't sure where to place them
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

#setting cronjob in user crontab for scanning and performance functions
def cronjob_setup():
    #make sure out script is executable, script should be in same dir 
    output = subprocess.run(["chmod","+x","./cronjob_setup.sh"], capture_output=True, text=True)
    print(output.stdout)
    print(output.stderr)
    #running bash script
    user_input = input("Please enter the cronjob interval for NetPi(Default 30 min):")
    result = subprocess.run(["./cronjob_setup.sh", user_input],capture_output=True, text=True)
    print(result.stdout)
    print(result.stderr)
    return

if __name__ == "__main__":
    package_installation()
    config_initialization()
    cronjob_setup()
    begin_web_ui()