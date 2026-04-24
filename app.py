import os
import json
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
from collections import Counter
from flask import Flask, render_template, request, jsonify
import uuid
import threading
import time

from pcap_processor import pcap_to_csv

app = Flask(__name__)
app.secret_key = "sentri_secret_key_2024"

# ---- LOAD MODELS ONCE AT STARTUP ----
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR  = os.path.join(BASE_DIR, "models")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
RESULT_FILE = os.path.join(UPLOAD_DIR, "latest_results.json")

hybrid_model  = joblib.load(os.path.join(MODEL_DIR, "hybrid_model_final.pkl"))
label_encoder = joblib.load(os.path.join(MODEL_DIR, "label_encoder_final.pkl"))
print("Models loaded ✓")

# ---- ANALYSIS STATUS TRACKING ----
analysis_status = {
    'status': 'idle',  # idle, pre-check, extracting, predicting, complete
    'file_name': None,
    'lock': threading.Lock()
}

def update_status(new_status, file_name=None):
    """Thread-safe status update"""
    with analysis_status['lock']:
        analysis_status['status'] = new_status
        if file_name is not None:
            analysis_status['file_name'] = file_name
        print(f"Status updated: {new_status}")

# ---- ML FEATURE COLUMNS (must match training exactly) ----
ML_FEATURES = [
	'flow_duration', 'Header_Length', 'Protocol Type', 'Duration',
	'Rate', 'Srate', 'Drate', 'fin_flag_number', 'syn_flag_number',
	'rst_flag_number', 'psh_flag_number', 'ack_flag_number',
	'ece_flag_number', 'cwr_flag_number', 'ack_count', 'syn_count',
	'fin_count', 'urg_count', 'rst_count', 'HTTP', 'HTTPS', 'DNS',
	'Telnet', 'SMTP', 'SSH', 'IRC', 'TCP', 'UDP', 'DHCP', 'ARP',
	'ICMP', 'IPv', 'LLC', 'Tot sum', 'Min', 'Max', 'AVG', 'Std',
	'Tot size', 'IAT', 'Number', 'Magnitue', 'Radius', 'Covariance',
	'Variance', 'Weight'
]
# Main to subcategory mapping for better organization in the UI
MAIN_CATEGORY_MAP = {
    "DDoS": [
        "DDoS-ICMP_Flood",
        "DDoS-UDP_Flood",
        "DDoS-TCP_Flood",
        "DDoS-PSHACK_Flood",
        "DDoS-SYN_Flood",
        "DDoS-RSTFINFlood",
        "DDoS-SynonymousIP_Flood",
        "DDoS-HTTP_Flood",
        "DDoS-SlowLoris",
        "DDoS-ICMP_Fragmentation",
        "DDoS-UDP_Fragmentation",
        "DDoS-ACK_Fragmentation",
    ],

    "DoS": [
        "DoS-UDP_Flood",
        "DoS-TCP_Flood",
        "DoS-SYN_Flood",
        "DoS-HTTP_Flood",
    ],

    "Brute Force": [
        "DictionaryBruteForce",
    ],

    "Spoofing": [
        "MITM-ArpSpoofing",
        "DNS_Spoofing",
    ],

    "Recon": [
        "Recon-PortScan",
        "Recon-OSScan",
        "Recon-HostDiscovery",
        "Recon-PingSweep",
        "VulnerabilityScan",
    ],

    "Web-based": [
        "SqlInjection",
        "XSS",
        "CommandInjection",
        "BrowserHijacking",
        "Uploading_Attack",
        "Backdoor_Malware",
    ],

    "Mirai": [
        "Mirai-greeth_flood",
        "Mirai-udpplain",
        "Mirai-greip_flood",
    ],

    "Benign": [
        "BenignTraffic"
    ]
}

TYPE_TO_CATEGORY = {}

for cat, items in MAIN_CATEGORY_MAP.items():
    for item in items:
        TYPE_TO_CATEGORY[item] = cat
        
def get_main_category(label):
    return TYPE_TO_CATEGORY.get(label, "Unknown")
# ---- SEVERITY MAPPING ----
SEVERITY_MAP = {
	'DDoS-ICMP_Flood':           'CRITICAL',
	'DDoS-UDP_Flood':            'CRITICAL',
	'DDoS-TCP_Flood':            'CRITICAL',
	'DDoS-PSHACK_Flood':         'CRITICAL',
	'DDoS-SYN_Flood':            'CRITICAL',
	'DDoS-RSTFINFlood':          'CRITICAL',
	'DDoS-SynonymousIP_Flood':   'CRITICAL',
	'DDoS-HTTP_Flood':           'CRITICAL',
	'DDoS-SlowLoris':            'CRITICAL',
	'DDoS-ICMP_Fragmentation':   'CRITICAL',
	'DDoS-UDP_Fragmentation':    'CRITICAL',
	'DDoS-ACK_Fragmentation':    'CRITICAL',
	'DoS-UDP_Flood':             'HIGH',
	'DoS-TCP_Flood':             'HIGH',
	'DoS-SYN_Flood':             'HIGH',
	'DoS-HTTP_Flood':            'HIGH',
	'Mirai-greeth_flood':        'HIGH',
	'Mirai-udpplain':            'HIGH',
	'Mirai-greip_flood':         'HIGH',
	'MITM-ArpSpoofing':          'HIGH',
	'Backdoor_Malware':          'HIGH',
	'Recon-PortScan':            'MEDIUM',
	'Recon-OSScan':              'MEDIUM',
	'Recon-HostDiscovery':       'MEDIUM',
	'Recon-PingSweep':           'MEDIUM',
	'DNS_Spoofing':              'MEDIUM',
	'VulnerabilityScan':         'MEDIUM',
	'DictionaryBruteForce':      'MEDIUM',
	'SqlInjection':              'LOW',
	'XSS':                       'LOW',
	'CommandInjection':          'LOW',
	'BrowserHijacking':          'LOW',
	'Uploading_Attack':          'LOW',
	'BenignTraffic':             'INFO',
}

RECOMMENDATIONS = {
	'DDoS-ICMP_Flood':           'Block ICMP flood traffic at the firewall. Apply rate limiting on ICMP packets. Consider upstream null-routing the source IP.',
	'DDoS-UDP_Flood':            'Enable UDP rate limiting on the router. Block spoofed source IPs. Contact your ISP for upstream filtering assistance.',
	'DDoS-TCP_Flood':            'Deploy TCP SYN cookies. Rate-limit new TCP connections per source IP. Block offending IPs at the network perimeter.',
	'DDoS-PSHACK_Flood':         'Filter PSH+ACK flood traffic at the firewall. Enable stateful packet inspection and alert the SOC team immediately.',
	'DDoS-SYN_Flood':            'Enable SYN cookies on affected servers. Rate-limit SYN packets per source IP. Deploy anti-spoofing ACLs at the network edge.',
	'DDoS-RSTFINFlood':          'Block RST/FIN flood at the network edge. Use stateful firewall rules to drop invalid TCP flag combinations.',
	'DDoS-SynonymousIP_Flood':   'Enable IP source verification (uRPF). Block private/reserved IPs arriving on external interfaces. Contact ISP for upstream filtering.',
	'DDoS-HTTP_Flood':           'Deploy a WAF with rate limiting. Implement CAPTCHA for high-traffic endpoints. Block offending source IPs immediately.',
	'DDoS-SlowLoris':            'Configure server connection timeouts. Limit simultaneous connections per IP. Use a reverse proxy with DDoS protection enabled.',
	'DDoS-ICMP_Fragmentation':   'Block fragmented ICMP packets at the firewall. Enable fragment reassembly limits to prevent resource exhaustion.',
	'DDoS-UDP_Fragmentation':    'Block fragmented UDP packets. Apply egress filtering. Enable anti-fragmentation policies on the perimeter firewall.',
	'DDoS-ACK_Fragmentation':    'Block fragmented ACK packets. Investigate upstream network for amplification sources and apply rate limiting.',
	'DoS-UDP_Flood':             'Rate-limit UDP traffic from the source IP. Block the offending host and alert the network administrator.',
	'DoS-TCP_Flood':             'Apply connection rate limiting. Block source IP at the perimeter firewall. Investigate the source device for compromise.',
	'DoS-SYN_Flood':             'Enable SYN proxy on the affected server. Block source IP and monitor for further SYN flood attempts.',
	'DoS-HTTP_Flood':            'Apply HTTP rate limiting in the WAF. Block the source IP. Monitor application logs for further abuse patterns.',
	'Mirai-greeth_flood':        'Isolate the infected IoT device immediately. Change default credentials. Apply firmware updates. Segment the IoT network.',
	'Mirai-udpplain':            'Isolate infected IoT device. Scan for Mirai indicators of compromise. Apply network segmentation for all IoT devices.',
	'Mirai-greip_flood':         'Take infected device offline. Perform factory reset and firmware update. Enforce IoT network isolation policy.',
	'MITM-ArpSpoofing':          'Enable Dynamic ARP Inspection (DAI) on switches. Use static ARP entries for critical devices. Enforce 802.1X authentication.',
	'Backdoor_Malware':          'Immediately isolate the affected device. Perform forensic analysis. Wipe and reimage if confirmed. Rotate all credentials.',
	'Recon-PortScan':            'Block the scanning source IP. Review exposed services and close unnecessary ports. Enable IDS alerting for future scans.',
	'Recon-OSScan':              'Block source IP. Harden service banners and OS fingerprints. Review firewall rules for unnecessarily exposed services.',
	'Recon-HostDiscovery':       'Block source IP from scanning. Enable network-level ping blocking where appropriate. Log and alert on all discovery attempts.',
	'Recon-PingSweep':           'Block ICMP from source IP. Enable egress filtering. Investigate whether the source is an internal compromised host.',
	'DNS_Spoofing':              'Enable DNSSEC on all DNS servers. Use encrypted DNS (DoH/DoT). Validate DNS responses and monitor for anomalies.',
	'VulnerabilityScan':         'Block scanning IP immediately. Patch identified vulnerabilities. If an internal scanner, review its scope and authorization.',
	'DictionaryBruteForce':      'Lock accounts after failed login attempts. Implement MFA immediately. Block source IP and review authentication logs.',
	'SqlInjection':              'Block source IP in WAF. Audit and sanitize all database queries. Use parameterized queries. Review application logs.',
	'XSS':                       'Block source IP. Implement Content Security Policy (CSP). Sanitize all user-supplied input. Review affected web endpoints.',
	'CommandInjection':          'Block source IP immediately. Audit all command execution paths. Apply strict input validation and sandboxing.',
	'BrowserHijacking':          'Investigate affected client devices for malware. Review browser extensions. Enforce endpoint security policies.',
	'Uploading_Attack':          'Block source IP. Restrict file upload types and sizes. Scan all uploads with antivirus. Audit server upload directories.',
	'BenignTraffic':             'No action required. Traffic appears normal and benign.',
}

DESCRIPTIONS = {
	'DDoS-ICMP_Flood':           'High-volume ICMP flood detected. Potential volumetric DDoS attack overwhelming network resources.',
	'DDoS-UDP_Flood':            'Massive UDP packet flood targeting the destination. Likely a volumetric DDoS attack.',
	'DDoS-TCP_Flood':            'TCP flood attack detected. High rate of TCP packets targeting the destination host.',
	'DDoS-PSHACK_Flood':         'PSH+ACK flood detected. High-volume TCP PSH+ACK packets sent to exhaust server resources.',
	'DDoS-SYN_Flood':            'TCP SYN flood detected. Half-open connections are exhausting the target server resources.',
	'DDoS-RSTFINFlood':          'RST/FIN flood detected. TCP RST and FIN packets sent to disrupt active connections.',
	'DDoS-SynonymousIP_Flood':   'Synonymous IP flood detected. Spoofed source IPs used to amplify DDoS impact.',
	'DDoS-HTTP_Flood':           'HTTP request flood detected. High volume of HTTP requests targeting the web application.',
	'DDoS-SlowLoris':            'SlowLoris attack detected. Attacker holding connections open to exhaust the server connection pool.',
	'DDoS-ICMP_Fragmentation':   'Fragmented ICMP flood detected. Fragmented packets used to evade detection and cause resource exhaustion.',
	'DDoS-UDP_Fragmentation':    'Fragmented UDP flood detected. Fragmented packets targeting the destination to cause resource exhaustion.',
	'DDoS-ACK_Fragmentation':    'Fragmented ACK flood detected. Fragmented TCP ACK packets used in a coordinated DDoS campaign.',
	'DoS-UDP_Flood':             'UDP flood denial-of-service attack detected originating from a single source.',
	'DoS-TCP_Flood':             'TCP flood denial-of-service attack detected from a single source targeting the host.',
	'DoS-SYN_Flood':             'SYN flood denial-of-service attack detected targeting the destination host.',
	'DoS-HTTP_Flood':            'HTTP flood denial-of-service detected targeting the web server.',
	'Mirai-greeth_flood':        'Mirai botnet GRE Ethernet flood detected. Infected IoT device participating in a botnet attack.',
	'Mirai-udpplain':            'Mirai botnet UDP plain flood detected. IoT device is likely infected with Mirai malware.',
	'Mirai-greip_flood':         'Mirai botnet GRE IP flood detected. Compromised IoT device sending coordinated flood traffic.',
	'MITM-ArpSpoofing':          'ARP spoofing detected. Attacker sending gratuitous ARP replies to poison network ARP tables.',
	'Backdoor_Malware':          'Backdoor malware communication detected. Device may be compromised and communicating with a C2 server.',
	'Recon-PortScan':            'Port scan detected. Single source scanning multiple destination ports in a classic reconnaissance pattern.',
	'Recon-OSScan':              'OS fingerprinting scan detected. Attacker probing to identify the operating system of the target host.',
	'Recon-HostDiscovery':       'Host discovery scan detected. Attacker mapping live hosts across the network.',
	'Recon-PingSweep':           'ICMP ping sweep detected. Attacker scanning the subnet to identify active hosts.',
	'DNS_Spoofing':              'DNS spoofing activity detected. Malicious DNS responses may redirect traffic to attacker-controlled servers.',
	'VulnerabilityScan':         'Vulnerability scan detected. Source is actively probing the target for exploitable weaknesses.',
	'DictionaryBruteForce':      'Dictionary brute force attack detected. Attacker attempting to guess credentials using a wordlist.',
	'SqlInjection':              'SQL injection attempt detected. Attacker attempting to manipulate the database through user input fields.',
	'XSS':                       'Cross-site scripting (XSS) attack detected. Malicious scripts are being injected into web traffic.',
	'CommandInjection':          'Command injection attack detected. Attacker attempting to execute system commands through the application.',
	'BrowserHijacking':          'Browser hijacking attempt detected. Malicious traffic attempting to redirect or control browser sessions.',
	'Uploading_Attack':          'Malicious file upload attack detected. Attacker attempting to upload potentially dangerous files to the server.',
	'BenignTraffic':             'Normal network traffic. No malicious activity detected in this flow.',
}


# ---- HELPERS ----

def decode_flags(row):
	flags = []
	if row.get('syn_flag_number', 0) > 0: flags.append('SYN')
	if row.get('ack_flag_number', 0) > 0: flags.append('ACK')
	if row.get('fin_flag_number', 0) > 0: flags.append('FIN')
	if row.get('rst_flag_number', 0) > 0: flags.append('RST')
	if row.get('psh_flag_number', 0) > 0: flags.append('PSH')
	if row.get('urg_count', 0) > 0:       flags.append('URG')
	if row.get('ece_flag_number', 0) > 0: flags.append('ECE')
	if row.get('cwr_flag_number', 0) > 0: flags.append('CWR')
	return '+'.join(flags) if flags else 'None'

def flow_score(t):
    return (
        t.get('bytes', 0) * 2 +
        t.get('packets', 0) * 2 +
        len(str(t.get('service', ''))) +
        len(str(t.get('protocol', ''))) +
        t.get('flow_count', 0)
    )

def deduplicate_threats(raw_threats):
    groups = {}

    for t in raw_threats:
        key = (t['type'], t['source_ip'], t['dest_ip'])

        if key not in groups:
            groups[key] = t.copy()
            groups[key]['flow_count'] = 1
            groups[key]['first_seen'] = t.get('timestamp')
        else:
            g = groups[key]

            # aggregate
            g['bytes'] += t.get('bytes', 0)
            g['packets'] += t.get('packets', 0)
            g['flow_count'] += 1
            
            g['fin_flag_number'] = g.get('fin_flag_number', 0) + t.get('fin_flag_number', 0)
            g['syn_flag_number'] = g.get('syn_flag_number', 0) + t.get('syn_flag_number', 0)
            g['rst_flag_number'] = g.get('rst_flag_number', 0) + t.get('rst_flag_number', 0)
            g['psh_flag_number'] = g.get('psh_flag_number', 0) + t.get('psh_flag_number', 0)
            g['ack_flag_number'] = g.get('ack_flag_number', 0) + t.get('ack_flag_number', 0)
            g['ece_flag_number'] = g.get('ece_flag_number', 0) + t.get('ece_flag_number', 0)
            g['cwr_flag_number'] = g.get('cwr_flag_number', 0) + t.get('cwr_flag_number', 0)
            g['urg_count']       = g.get('urg_count', 0) + t.get('urg_count', 0)

            # keep EARLIEST timestamp
            if t.get('timestamp') < g.get('first_seen'):
                g['first_seen'] = t.get('timestamp')

            # keep MOST INFORMATIVE flow (score-based)
            if flow_score(t) > flow_score(g):
                g['service'] = t.get('service', g.get('service'))
                g['protocol'] = t.get('protocol', g.get('protocol'))
                g['source_mac'] = t.get('source_mac', g.get('source_mac'))
                g['dest_mac'] = t.get('dest_mac', g.get('dest_mac'))

    unique = []
    for t in groups.values():
        if t['flow_count'] > 1:
            t['description'] += f" ({t['flow_count']} flows aggregated)"
        unique.append(t)

    return unique


def generate_correlations(threats):

    # attach main category properly
    for t in threats:
        t["main_category"] = get_main_category(t["type"])

    correlations = []
    attack_types = [t['type'] for t in threats if t['type'] != 'BenignTraffic']
    src_ips      = [t['source_ip'] for t in threats if t['type'] != 'BenignTraffic']

    recon = [t for t in threats if t['main_category'] == 'Recon']
    ddos  = [t for t in threats if t['main_category'] in ['DDoS', 'DoS']]

    if recon and ddos:
        correlations.append(
            f"Reconnaissance activity from {recon[0]['source_ip']} precedes flood attack — "
            "suggests a coordinated reconnaissance-to-exploit attack chain."
        )

    src_counter = Counter(src_ips)
    for ip, count in src_counter.items():
        if count >= 2:
            correlations.append(
                f"Source IP {ip} is responsible for {count} distinct threat types — "
                "likely a persistent attacker or compromised device."
            )

    mirai = [t for t in threats if t['main_category'] == 'Mirai']
    if mirai and ddos:
        correlations.append(
            "Mirai botnet traffic correlates with DDoS/DoS flood activity — "
            "infected IoT devices may be participating in a coordinated botnet campaign."
        )

    arp = [t for t in threats if t['type'] in ['MITM-ArpSpoofing', 'ARP']]
    if arp and len(attack_types) > 1:
        correlations.append(
            "ARP spoofing combined with other attacks suggests a potential man-in-the-middle setup."
        )

    internal = [t for t in threats
                if t['source_ip'].startswith(('192.168.', '10.', '172.'))
                and t['type'] != 'BenignTraffic']

    if internal:
        pct = round(len(internal) / max(len(threats), 1) * 100)
        correlations.append(
            f"{pct}% of flagged flows originate from internal IP addresses — "
            "suggesting compromised internal devices or insider threat activity."
        )

    return correlations[:5]


# ============================================================
# ROUTES
# ============================================================

@app.route('/')
def index():
	return render_template('index.html')

@app.route('/loading')
def loading():
    return render_template('loading.html')

@app.route('/results')
def results():
	if not os.path.exists(RESULT_FILE):
		return render_template('index.html')

	with open(RESULT_FILE, 'r') as f:
		data = json.load(f)

	threat_ratio      = data.get("threat_ratio", 0)
	threat_ratio_dash = round((threat_ratio / 100) * 188.5, 1)

	return render_template(
		"results.html",
		total_flows       = data["total_flows"],
		malicious_count   = data["malicious_count"],
		threats           = data["threats"],
		correlations      = data.get("correlations", []),
		threat_ratio      = threat_ratio,
		threat_ratio_dash = threat_ratio_dash,
	)

@app.route('/status', methods=['GET'])
def status():
	"""Return current analysis status for frontend polling"""
	with analysis_status['lock']:
		return jsonify({
			'status': analysis_status['status'],
			'file_name': analysis_status['file_name']
		})

@app.route('/analyze', methods=['POST'])
def analyze():
	file = request.files.get('file')
	if not file:
		return jsonify({"error": "No file uploaded"}), 400

	os.makedirs(UPLOAD_DIR, exist_ok=True)
	
	# Update status: pre-check
	update_status('pre-check', file.filename)
	
	# Create unique filenames to prevent file locking issues on Windows
	unique_id = str(uuid.uuid4())[:8]
	pcap_path   = os.path.join(UPLOAD_DIR, file.filename)
	display_csv = os.path.join(UPLOAD_DIR, f"display_records_{unique_id}.csv")
	model_csv   = os.path.join(UPLOAD_DIR, f"prediction_ready_{unique_id}.csv")
	
	print(f"\n========== ANALYSIS START ==========")
	print(f"File: {file.filename}")
	print(f"PCAP path: {pcap_path}")
	
	try:
		file.save(pcap_path)
		print(f"✓ File saved successfully")
	except Exception as e:
		print(f"✗ File save failed: {e}")
		update_status('idle')
		return jsonify({"error": f"Failed to save file: {str(e)}"}), 500

	# Small delay to ensure pre-check phase is visible
	time.sleep(0.5)
	
	# Update status: extracting features
	update_status('extracting')
	
	# ---- EXTRACT FEATURES ----
	try:
		print(f"→ Starting feature extraction...")
		result = pcap_to_csv(pcap_path, display_csv, model_csv, window_size=10)
		if result is None:
			print(f"✗ Feature extraction returned None")
			update_status('idle')
			return jsonify({"error": "No flows could be extracted from the PCAP file."}), 400
		df_display, df_model = result
		print(f"✓ Feature extraction complete: {len(df_model)} flows extracted")
	except Exception as e:
		print(f"✗ Feature extraction failed: {str(e)}")
		import traceback
		traceback.print_exc()
		update_status('idle')
		return jsonify({"error": f"Feature extraction failed: {str(e)}"}), 500

	if df_model.empty:
		print(f"✗ No valid flows in df_model")
		update_status('idle')
		return jsonify({"error": "No valid flows extracted from PCAP."}), 400

	# Small delay to ensure extracting phase is visible
	time.sleep(0.5)
	
	# Update status: running prediction
	update_status('predicting')
	
	# ---- RUN MODEL ----
	try:
		print(f"→ Running ML model prediction...")
		X = df_model[ML_FEATURES].fillna(0)
		predictions      = hybrid_model.predict(X)
		predicted_labels = label_encoder.inverse_transform(predictions)
		print(f"✓ Model prediction complete: {len(predictions)} predictions")
	except Exception as e:
		print(f"✗ Model prediction failed: {str(e)}")
		import traceback
		traceback.print_exc()
		update_status('idle')
		return jsonify({"error": f"Model prediction failed: {str(e)}"}), 500

	# Small delay to ensure predicting phase is visible
	time.sleep(0.5)
	
	# ---- BUILD RAW THREATS LIST ----
	raw_threats = []
	df_display  = df_display.reset_index(drop=True)
	df_model    = df_model.reset_index(drop=True)

	for i, label in enumerate(predicted_labels):
		if label == 'BenignTraffic':
			continue

		row_d = df_display.iloc[i].to_dict() if i < len(df_display) else {}
		row_m = df_model.iloc[i].to_dict()

		raw_dur = row_m.get('flow_duration', 0)
		duration_str = f"{round(raw_dur * 1000)}ms" if raw_dur < 1 else f"{round(raw_dur, 2)}s"

		raw_threats.append({
			"type":           label,
			"category": get_main_category(label),
			"severity":       SEVERITY_MAP.get(label, 'INFO'),
			"description":    DESCRIPTIONS.get(label, f"{label} detected."),
			"recommendation": RECOMMENDATIONS.get(label, "Investigate and take appropriate action."),
			"source_ip":      row_d.get('Src_IP', 'N/A'),
			"dest_ip":        row_d.get('Dst_IP', 'N/A'),
			"source_mac":     row_d.get('Src_MAC', 'N/A'),
			"dest_mac":       row_d.get('Dst_MAC', 'N/A'),
			"protocol":       row_d.get('Protocol_Name', 'N/A'),
			"service":        row_d.get('Service', 'N/A'),
			"timestamp":      row_d.get('Timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
			"bytes":          int(row_d.get('Tot size', row_m.get('Tot size', 0))),
			"packets":        int(row_d.get('Number',   row_m.get('Number', 0))),
			"duration":       duration_str,
			"flags":          decode_flags(row_m),
		})

	# ---- DEDUPLICATE ----
	threats = deduplicate_threats(raw_threats)

	# ---- SORT BY SEVERITY ----
	severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
	threats.sort(key=lambda x: severity_order.get(x['severity'], 5))

	# ---- SUMMARY STATS ----
	total_flows     = len(df_display)
	malicious_count = len(threats)
	threat_ratio    = round(malicious_count / total_flows * 100, 1) if total_flows > 0 else 0
	correlations    = generate_correlations(threats)

	result_data = {
		"total_flows":     total_flows,
		"malicious_count": malicious_count,
		"threat_ratio":    threat_ratio,
		"threats":         threats,
		"correlations":    correlations,
	}	
	with open(RESULT_FILE, 'w') as f:
		json.dump(result_data, f)
	
	print(f"✓ Results saved to: {RESULT_FILE}")
	print(f"  Total flows: {total_flows}, Malicious: {malicious_count}, Ratio: {threat_ratio}%")
	print(f"========== ANALYSIS END ==========\n")

	# Clean up temporary CSV files
	try:
		if os.path.exists(display_csv):
			os.remove(display_csv)
		if os.path.exists(model_csv):
			os.remove(model_csv)
		if os.path.exists(pcap_path):
			os.remove(pcap_path)
		print(f"✓ Temporary files cleaned up")
	except Exception as e:
		print(f"⚠ Warning: Could not delete temporary files: {e}")

	# Update status to complete
	update_status('complete')
	
	return jsonify(result_data)


if __name__ == '__main__':
	app.run(debug=True)