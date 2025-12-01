from flask import Flask, render_template, request, jsonify, send_file, request
import socket
import time
import shutil
import csv, os
import sys
from datetime import datetime
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parent_dir)

import Functions.scan as scan_module
import Functions.peformance as perf_module
import Functions.clear_cache as cache_module
import Functions.sniffer as sniff_module
import Functions.arp_spoof as arp_module

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")
"""
- scanning network for devices
"""
@app.route("/scan", methods=["GET", "POST"])
def scan():
    # When GET request, load saved devices and render scan page
    if request.method == 'GET':
        try:
            saved = scan_module.load_devices()
        except Exception:
            saved = []
        return render_template("scan.html", devices=saved)
    
    # When POST request, perform network scan
    try:
        # Load scan configuration
        scan_module.setup_config()
        addr = scan_module.config.get('address', '<address>')
        dns = scan_module.config.get('dns', None)
        subnet = scan_module.config.get('subnet', '24')

        devices = scan_module.scan_network(addr, dns, subnet)
        scan_module.save_devices(devices)

        # Return JSON response for frontend
        return jsonify(status='ok', devices=len(devices))
    except Exception as e:
        return jsonify(status='error', message=str(e)), 500

"""
- performance measurement of network devices
"""
@app.route("/performance", methods=["GET", "POST"])
def performance():
    # When GET request, load performance log and render performance page
    if request.method == 'GET':
        perf_rows = []
        perf_file = os.path.join('CSV', 'performance_log.csv')
        # Load existing performance log if available
        if os.path.exists(perf_file):
            try:
                # Read performance log CSV and populate rows
                with open(perf_file, 'r', newline='') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        perf_rows.append(row)
            except Exception:
                perf_rows = []

        return render_template("performance.html", perf_rows=perf_rows)

    try:
        # On POST request, perform performance measurement
        devices = perf_module.load_devices()
        if not devices:
            return jsonify(status='error', message='No saved devices'), 400

        # Perform performance measurement on devices
        measured = perf_module.measure_performance(devices)
        perf_module.log_performance_data(measured)

        # Return JSON response for frontend
        return jsonify(status='ok', devices=len(measured))
    except Exception as e:
        return jsonify(status='error', message=str(e)), 500

@app.route("/reports")
def reports():
    return render_template("reports.html")
@app.route("/sniffer", methods=["GET", "POST"], endpoint='sniffer')
def webSniff(): 
    if request.method == 'GET':
        devices = []
        devices_file = 'CSV/saved_devices.csv'
        if os.path.exists(devices_file):
            try:
                with open(devices_file, 'r', newline='') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        devices.append({
                            'ip': row.get('IP', row.get('ip', '')),
                            'hostname': row.get('Hostname', row.get('hostname', row.get('IP', 'Unknown')))
                        })
            except Exception as e:
                print(f"Error loading devices: {e}")
                devices = []
        return render_template("sniffer.html", devices=devices)
    
    try:
        duration = int(request.form.get('duration', 10))
        protocol_filter = request.form.get('filter', '')
        target = request.form.get('device', '').strip()
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pcap_filename = f"capture_{timestamp}.pcap"
        
        # Get my IP and gateway
        my_ip_addr = get_host_ip()
        gateway_ip = None
        config_file = '.config'
        
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                for line in f:
                    if line.startswith('router='):
                        gateway_ip = line.split('=')[1].strip()
                        break
        
        print(f"\n=== DEBUG: Starting capture ===")
        print(f"My IP: {my_ip_addr}")
        print(f"Target IP: {target if target else 'All (no MITM)'}")
        print(f"Gateway: {gateway_ip}")
        print(f"Duration: {duration} seconds")
        
        # Determine if we need ARP spoofing
        needs_mitm = target and target != my_ip_addr and target != ''
        
        if needs_mitm:
            # Start ARP spoofing
            success, message = arp_module.start_arp_spoof(target, gateway_ip)
            if not success:
                return render_template("sniffer.html", 
                                     message=f"ARP Spoof Error: {message}",
                                     status_type='error',
                                     devices=[])
            print(f"✓ ARP spoofing started")
            # Give ARP spoofing time to take effect
            time.sleep(3)
        
        try:
            # Capture packets
            print(f"Starting packet capture for {duration} seconds...")
            sniff_module.sniffer(pcap_filename, time=duration)
            print(f"✓ Capture complete")
        finally:
            # Always stop ARP spoofing when done
            if needs_mitm:
                print("Stopping ARP spoofing...")
                arp_module.stop_arp_spoof()
                print("✓ ARP spoofing stopped")
        
        # Create captures directory
        os.makedirs('captures', exist_ok=True)
        
        # Move PCAP to captures directory
        pcap_path = f'captures/{pcap_filename}'
        shutil.move(pcap_filename, pcap_path)
        
        # *** CRITICAL: Filter BEFORE analyzing ***
        if needs_mitm:
            print(f"Filtering MITM traffic for {target}...")
            sniff_module.filter_mitm_traffic(pcap_path, target)
        
        # NOW analyze the (potentially filtered) pcap
        print(f"Analyzing PCAP: {pcap_path}")
        sniff_module.analyze_pcap(pcap_path)
        
        # Move CSV files to captures directory with timestamp
        csv_files = ['protocols.csv', 'top_ips.csv', 'top_ports.csv', 'dns_queries.csv']
        for csv_file in csv_files:
            if os.path.exists(csv_file):
                new_name = csv_file.replace('.csv', f'_{timestamp}.csv')
                shutil.move(csv_file, f'captures/{new_name}')
        
        # Read the stats from the timestamped CSV
        stats = {
            'total': 0,
            'tcp': 0,
            'udp': 0,
            'icmp': 0,
            'arp': 0
        }
        
        protocols_csv = f'captures/protocols_{timestamp}.csv'
        with open(protocols_csv, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                proto = row['Protocol'].lower()
                count = int(row['Count'])
                stats['total'] += count
                if proto in stats:
                    stats[proto] = count
        
        # If a protocol filter was selected, filter the packets
        if protocol_filter:
            print(f"Applying protocol filter: {protocol_filter}")
            sniff_module.filter_packets(pcap_path, protocol_filter)
        
        mitm_note = f" (MITM: {target})" if needs_mitm else ""
        
        return render_template("sniffer.html", 
                             stats=stats, 
                             message=f"Successfully captured {stats['total']} packets{mitm_note}",
                             status_type='success',
                             pcap_file=pcap_filename,
                             devices=[])
    
    except Exception as e:
        # Emergency cleanup
        try:
            arp_module.stop_arp_spoof()
        except:
            pass
        
        import traceback
        traceback.print_exc()
        return render_template("sniffer.html", 
                             message=f"Error: {str(e)}",
                             status_type='error',
                             devices=[])


@app.route("/sniffer/analysis", methods = ["GET", "POST"], endpoint="sniffer_analysis")
def sniffer_analysis():
    print(f"\n=== ANALYSIS DEBUG ===")
    captures_dir = 'captures'
    if not os.path.exists(captures_dir):
        os.makedirs(captures_dir)
    
    pcap_files = [f for f in os.listdir(captures_dir) if f.endswith('.pcap')]
    pcap_files.sort(reverse=True)  # get most recent file 
    
    analysis_data = None
    filename = request.args.get('filename')
    if filename and filename in pcap_files:
        print("using selected file")
    elif pcap_files:
        # Default to most recent
        filename = pcap_files[0]
        print(f"Analyzing most recent file: {filename}")
    
    # Now analyze the selected filename
    if filename:  # <-- CHANGE from "if pcap_files:" to "if filename:"
        print(f"Analyzing most recent file: {filename}")
        
        pcap_path = os.path.join(captures_dir, filename)
        
        # Extract timestamp from filename
        timestamp = filename.replace('capture_', '').replace('.pcap', '')
        
        # CSV filenames
        protocols_csv = f'protocols_{timestamp}.csv'
        ips_csv = f'top_ips_{timestamp}.csv'
        ports_csv = f'top_ports_{timestamp}.csv'
        dns_csv = f'dns_queries_{timestamp}.csv'
        
        # Check if analysis CSVs exist, if not, run analysis
        if not os.path.exists(f'captures/{protocols_csv}'):
            print(f"Generating analysis for {filename}...")
            sniff_module.analyze_pcap(pcap_path)
            # Move generated CSVs
            for csv_file in ['protocols.csv', 'top_ips.csv', 'top_ports.csv', 'dns_queries.csv']:
                if os.path.exists(csv_file):
                    new_name = csv_file.replace('.csv', f'_{timestamp}.csv')
                    shutil.move(csv_file, f'captures/{new_name}')
        
        # Read protocol data
        protocols = []
        total_packets = 0
        protocols_path = f'captures/{protocols_csv}'
        
        if os.path.exists(protocols_path):
            with open(protocols_path, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    count = int(row['Count'])
                    total_packets += count
                    protocols.append(row)
            
            # Add percentages
            for proto in protocols:
                proto['Percentage'] = round((int(proto['Count']) / total_packets * 100), 1) if total_packets > 0 else 0
        
        # Read IP data
        top_ips = []
        unique_ips = set()
        ips_path = f'captures/{ips_csv}'
        
        if os.path.exists(ips_path):
            with open(ips_path, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    top_ips.append(row)
                    unique_ips.add(row['IP Address'])
        
        # Read port data
        top_ports = []
        unique_ports = set()
        ports_path = f'captures/{ports_csv}'
        
        if os.path.exists(ports_path):
            with open(ports_path, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    top_ports.append(row)
                    unique_ports.add(row['Port'])
        
        # Read DNS data
        dns_queries = []
        dns_path = f'captures/{dns_csv}'
        
        if os.path.exists(dns_path):
            with open(dns_path, 'r') as f:
                reader = csv.DictReader(f)
                dns_queries = list(reader)
        
        # Generate insights
        
        analysis_data = {
            'filename': filename,
            'total_packets': total_packets,
            'unique_ips': len(unique_ips),
            'unique_ports': len(unique_ports),
            'protocols': protocols,
            'top_ips': top_ips,
            'top_ports': top_ports,
            'dns_queries': dns_queries,
            'protocols_csv': protocols_csv,
            'ips_csv': ips_csv,
            'ports_csv': ports_csv,
            'dns_csv': dns_csv if dns_queries else None
        }
    
    return render_template("sniffer_analysis.html", 
                         pcap_files=pcap_files,
                         analysis=analysis_data,
                         selected_file=filename)
    
    # Get list of all saved captures
@app.route('/download/<filename>')
def download_file(filename):
    """Download CSV/log/pcap files"""
    file_paths = {
        'saved_devices.csv': 'CSV/saved_devices.csv',
        'performance_log.csv': 'CSV/performance_log.csv',
        'output.pcap': 'output.pcap',
        'scan.log': 'scheduled_logs/scan.log',
        'performance.log': 'scheduled_logs/performance.log'
    }
    
    file_path = file_paths.get(filename)
    if file_path and os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        return "File not found", 404

def get_host_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("1.1.1.1", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

def begin_web_ui():
    host_ip = get_host_ip()
    print(f"Starting Web UI on http://{host_ip}:1234")
    app.run(host=host_ip, port=1234, debug=False, use_reloader=False)

if __name__ == "__main__":
    begin_web_ui()
