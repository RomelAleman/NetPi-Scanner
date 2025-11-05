from flask import Flask, render_template, request
import socket

app = Flask(__name__)

# Can add main menu/dashboard here
@app.route('/')
def index():
    return render_template('index.html')

# Making another page for scanning, need to create scan.html in templates
"""
@app.route('/scan')
def scan():
    return render_template('scan.html')
"""

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

"""if __name__ == '__main__':
    begin_web_ui()"""