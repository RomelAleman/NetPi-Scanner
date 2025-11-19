#!/usr/bin/env python3

"""
- Parser for command-line arguments for NetPi-Scanner
- Supports options for scanning, performance measurement, web UI launch, and configuration management
- Integrates with other modules to execute requested functionalities
"""

import argparse
import Functions.scan as scan_module
import Functions.peformance as performance_module
import WebUI.host as webui_module

def parse_arguments():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='NetPi-Scanner Command-Line Interface')
    
    parser.add_argument('-s',
                        '--scan',
                        action='store_true', 
                        help='Scan the network')
    parser.add_argument('-p',
                        '--performance',
                        action='store_true',  
                        help='Measure performance of scanned devices')
    parser.add_argument('-w',
                        '--webui',
                        action='store_true',  
                        help='Launch the Web UI')
    parser.add_argument('-u', 
                        '--update-config', 
                        action='store_true',  
                        help='Update .config file')
    
    args = parser.parse_args()
    return args

def main():
    args = parse_arguments()

    if args.update_config:
        scan_module.update_config()
        print(".config file updated.")

    if args.scan:
        scan_module.setup_config()
        addr = scan_module.config.get('address', '<address>')
        dns_addr = scan_module.config.get('dns', '<dns_server>')

        devices = scan_module.scan_network(addr, dns_addr, scan_module.config.get('subnet', '24')) 

        scan_module.save_devices(devices)
        print("Network scan completed and devices saved.")

    if args.performance:
        devices = performance_module.load_devices()
        if devices:
            performance_module.measure_performance(devices)
            performance_module.log_performance_data(devices)
            print("Performance measurement completed and data logged.")
        else:
            print("No devices found to measure performance.")

    if args.webui:
        webui_module.begin_web_ui()
        print("Web UI launched.")

if __name__ == "__main__":
    main()