from flask import Flask, render_template, request, jsonify
import socket
import csv, os
import Functions.scan as scan_module
import Functions.peformance as perf_module
import Functions.clear_cache as cache_module

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
