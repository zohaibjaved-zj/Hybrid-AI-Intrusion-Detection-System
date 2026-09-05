# app.py  AI-Based Lightweight Web Intrusion Detection System

import warnings
warnings.filterwarnings("ignore")

from flask import Flask, render_template
from flask_socketio import SocketIO
from scapy.all import sniff, IP, TCP, UDP, Raw
import joblib
import numpy as np
import requests
from datetime import datetime
import threading
import time
import re
import urllib.parse

class Colors:
    RED = '\033[91m'
    ORANGE = '\033[93m'
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    END = '\033[0m'
    BOLD = '\033[1m'

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

print(f"{Colors.BOLD}{Colors.CYAN}╔══════════════════════════════════════════════════════════╗{Colors.END}")
print(f"{Colors.BOLD}{Colors.CYAN}║    AI-BASED LIGHTWEIGHT WEB INTRUSION DETECTION SYSTEM   ║{Colors.END}")
print(f"{Colors.BOLD}{Colors.CYAN}╚══════════════════════════════════════════════════════════╝{Colors.END}\n")

print(f"{Colors.BLUE}Loading models...{Colors.END}")
try:
    pipeline = joblib.load("models/ids_pipeline.joblib")
    rf = pipeline['rf']
    isof = pipeline['isof']
    scaler = pipeline['scaler']
    pca = pipeline['pca']
    le = pipeline['le']
    features = pipeline['features']
    print(f"{Colors.GREEN}✓ Models loaded!{Colors.END}")
except Exception as e:
    print(f"{Colors.RED}✗ Load failed: {e}{Colors.END}")
    exit(1)

alerts = []
totals = {"known": 0, "zeroday": 0, "web": 0}
packet_count = 0
start_time = time.time()
MAX_ALERTS = 200

# Simple regex patterns for common web attacks (lightweight signatures)
WEB_ATTACK_PATTERNS = [
    r"(?:')|(?:--)|(?:#)|(?:/\*.*?\*/)|(?:union.*select)|(?:select.*from)|(?:drop.*table)",
    r"<script.*?>.*?</script>|javascript:|onerror=|onload=|alert\(",
    r"(\.\./)|(\.\.%2f)|(%2e%2e%2f)|cmd=|exec\(|system\(",
    r"union\s+select|information_schema|@@version"
]

def is_web_attack(payload):
    if not payload:
        return False, "Normal"
    payload_str = payload.decode('utf-8', errors='ignore').lower()
    for pattern in WEB_ATTACK_PATTERNS:
        if re.search(pattern, payload_str):
            if "union" in pattern or "select" in pattern:
                return True, "SQL Injection"
            elif "script" in pattern or "javascript" in pattern:
                return True, "XSS"
            elif "../" in pattern or "cmd" in pattern:
                return True, "Path Traversal / RCE"
    return False, "Normal"

def geo_lookup(ip):
    private_ranges = ['10.', '172.', '192.168.', '127.', '169.254.', '::1']
    if any(ip.startswith(pr) for pr in private_ranges):
        return {"country": "Private Network", "city": "Internal", "isp": "LAN"}
    try:
        resp = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5).json()
        if resp.get('error'):
            return {"country": "Blocked", "city": "Rate Limited", "isp": "API"}
        return {
            "country": resp.get("country_name", "Unknown"),
            "city": resp.get("city", "Unknown"),
            "isp": resp.get("org", "Unknown")
        }
    except:
        return {"country": "Offline", "city": "Timeout", "isp": "No API"}

def predict_hybrid(feature_vector_pca):
    try:
        rf_pred = rf.predict([feature_vector_pca])[0]
        benign_idx = le.transform(['BENIGN'])[0]
        if rf_pred != benign_idx:
            return "Known Attack"
        elif isof.predict([feature_vector_pca])[0] == -1:
            return "Zero-Day Anomaly"
        return "Normal"
    except:
        return "Normal"

def extract_features(pkt):
    if IP in pkt:
        proto = 6 if TCP in pkt else (17 if UDP in pkt else 0)
        sport = getattr(pkt[TCP if TCP in pkt else IP], 'sport', 0) if TCP in pkt or UDP in pkt else 0
        dport = getattr(pkt[TCP if TCP in pkt else IP], 'dport', 0) if TCP in pkt or UDP in pkt else 0
        return {
            'Flow Duration': 1000,
            'Total Fwd Packets': 1,
            'Total Backward Packets': 0,
            'Fwd Packet Length Mean': len(pkt),
            'Protocol': proto,
            'Source Port': sport,
            'Destination Port': dport,
            'Flow Packets/s': 1000,
            'Fwd Packet Length Max': len(pkt)
        }
    return None

def packet_callback(pkt):
    global packet_count, totals
    packet_count += 1

    # Web-specific: Look for HTTP traffic (port 80/443/5000)
    is_http = False
    payload = None
    if TCP in pkt and pkt[TCP].dport in [80, 443, 5000]:
        if Raw in pkt:
            payload = pkt[Raw].load
            is_http = True

    feats = extract_features(pkt)
    if not feats:
        return

    try:
        vec = np.array([[feats.get(f, 0) for f in features]])
        scaled = scaler.transform(vec)
        pca_vec = pca.transform(scaled)
        
        ml_pred = predict_hybrid(pca_vec[0])

        web_attack = False
        web_type = "Normal"
        if is_http and payload:
            web_attack, web_type = is_web_attack(payload)

        final_pred = ml_pred
        if web_attack:
            final_pred = f"Web Attack ({web_type})"
            totals["web"] += 1
            color = Colors.PURPLE
        elif ml_pred == "Known Attack":
            totals["known"] += 1
            color = Colors.RED
        elif ml_pred == "Zero-Day Anomaly":
            totals["zeroday"] += 1
            color = Colors.ORANGE
        else:
            return  # Normal traffic

        attacker_ip = pkt[IP].src
        geo = geo_lookup(attacker_ip)
        
        alert = {
            "ip": attacker_ip,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "location": f"{geo['country']} / {geo['city']}",
            "type": final_pred,
            "protocol": "HTTP" if is_http else "TCP"
        }
        
        alerts.append(alert)
        if len(alerts) > MAX_ALERTS:
            alerts.pop(0)
        
        socketio.emit('new_alert', alert)
        print(f"{color}🚨 {final_pred.upper():<25} | {attacker_ip:<15} → {geo['country']:<20} / {geo['city']}{Colors.END}")
        
    except:
        pass

@app.route('/')
def index():
    uptime = time.time() - start_time
    hours, rem = divmod(uptime, 3600)
    minutes, seconds = divmod(rem, 60)
    uptime_str = f"{int(hours):02}h:{int(minutes):02}m:{int(seconds):02}s"
    
    return render_template('dashboard.html', 
                         alerts=alerts[-50:], 
                         totals=totals,
                         packet_count=packet_count,
                         uptime=uptime_str)

def start_sniffing():
    print(f"{Colors.GREEN}Starting capture → Network + Web Attacks (HTTP Payload){Colors.END}")
    print(f"{Colors.PURPLE}Test: Send SQLi/XSS to http://YOUR_IP:5000{Colors.END}\n")
    sniff(prn=packet_callback, filter="tcp port 80 or tcp port 443 or tcp port 5000 or udp", store=False, iface=None)

if __name__ == '__main__':
    threading.Thread(target=start_sniffing, daemon=True).start()
    print(f"{Colors.BOLD}{Colors.GREEN}LIGHTWEIGHT WEB IDS IS ACTIVE!{Colors.END}")
    print(f"{Colors.CYAN}→ http://localhost:5000{Colors.END}\n")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, use_reloader=False)