from flask import Flask, render_template, request, jsonify, send_file
import socket
import csv, os
import sys
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parent_dir)

import Functions.scan as scan_module
import Functions.peformance as perf_module
import Functions.clear_cache as cache_module
import Functions.sniffer as sniff_module

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
        return render_template("sniffer.html")
    try:
        duration = int(request.form.get('duration', 10))
        protocol_filter = request.form.get('filter', '')
        interface = request.form.get('interface', '')

        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pcap_filename = f"capture_{timestamp}.pcap"
        
        sniff_module.sniffer(pcap_filename,time=duration)
        sniff_module.analyze_pcap(pcap_filename)
        import csv
        stats = {
            'total': 0,
            'tcp': 0,
            'udp': 0,
            'icmp': 0,
            'arp': 0
        }
        
        with open('protocols.csv', 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                proto = row['Protocol'].upper()
                count = int(row['Count'])
                stats['total'] += count
                if proto in stats:
                    stats[proto.lower()] = count
        
        # If a protocol filter was selected, filter the packets
        if protocol_filter:
            sniff_module.filter_packets("output.pcap", protocol_filter)
        
        return render_template("sniffer.html", 
                             stats=stats, 
                             message=f"Successfully captured {stats['total']} packets for {duration} seconds",
                             status_type='success')
        
        
        # If a protocol filter was selected, filter the packets
        if protocol_filter:
            sniff_module.filter_packets("output.pcap", protocol_filter)
        
        # Run full analysis to generate CSV files
        sniff_module.analyze_pcap("output.pcap")
        
        return render_template("sniffer.html", 
                             stats=stats, 
                             message=f"Successfully captured {len(packets)} packets for {duration} seconds",
                             status_type='success')
    
    except Exception as e:
        return render_template("sniffer.html", 
                             message=f"Error during capture: {str(e)}",
                             status_type='error')

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
