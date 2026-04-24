import pandas as pd
import numpy as np
from scapy.all import rdpcap, IP, TCP, UDP, DNS, ARP, ICMP, IPv6
from scapy.layers.http import HTTP
from scapy.all import Ether
import math
from collections import defaultdict
import warnings
warnings.filterwarnings('ignore')

def extract_features_from_pcap(pcap_file, window_size=10):
    """
    Extract features from pcap file matching CIC-IoT2023 dataset columns
    """
    print(f"Reading pcap file: {pcap_file}")
    packets = rdpcap(pcap_file)
    print(f"Total packets loaded: {len(packets)}")

    # ---- GROUP PACKETS INTO FLOWS ----
    flows = defaultdict(list)
    for pkt in packets:
        if IP in pkt:
            # Flow key: src_ip, dst_ip, protocol
            proto = pkt[IP].proto
            src = pkt[IP].src
            dst = pkt[IP].dst
            flow_key = (src, dst, proto)
            flows[flow_key].append(pkt)

    print(f"Total flows found: {len(flows)}")

    # ---- EXTRACT FEATURES PER FLOW WINDOW ----
    records = []

    for flow_key, pkts in flows.items():
        src_ip, dst_ip, proto = flow_key

        # Process in windows
        for i in range(0, len(pkts), window_size):
            window = pkts[i:i+window_size]
            if len(window) < 2:
                continue

            record = extract_window_features(window, proto)
            if record:
                records.append(record)

    df = pd.DataFrame(records)
    print(f"Total records extracted: {len(df)}")
    return df

def best_window(window):
    # pick packet with most data (most "informative" packet)
    return max(window, key=lambda pkt: len(pkt))

def extract_window_features(window, proto):
    """Extract all 46 features from a window of packets"""
    try:
        timestamps = []
        pkt_sizes = []
        header_lengths = []

        # Flag counters
        fin_flags = 0
        syn_flags = 0
        rst_flags = 0
        psh_flags = 0
        ack_flags = 0
        ece_flags = 0
        cwr_flags = 0
        urg_flags = 0

        # Protocol flags
        has_http = 0
        has_https = 0
        has_dns = 0
        has_telnet = 0
        has_smtp = 0
        has_ssh = 0
        has_irc = 0
        has_tcp = 0
        has_udp = 0
        has_dhcp = 0
        has_arp = 0
        has_icmp = 0
        has_ipv = 0
        has_llc = 0

        for pkt in window:
            # Timestamp
            timestamps.append(float(pkt.time))

            # Packet size
            pkt_sizes.append(len(pkt))

            # Header length
            if IP in pkt:
                header_lengths.append(pkt[IP].ihl * 4)
                has_ipv = 1

            # TCP features
            if TCP in pkt:
                has_tcp = 1
                flags = pkt[TCP].flags
                fin_flags += 1 if flags & 0x01 else 0
                syn_flags += 1 if flags & 0x02 else 0
                rst_flags += 1 if flags & 0x04 else 0
                psh_flags += 1 if flags & 0x08 else 0
                ack_flags += 1 if flags & 0x10 else 0
                urg_flags += 1 if flags & 0x20 else 0
                ece_flags += 1 if flags & 0x40 else 0
                cwr_flags += 1 if flags & 0x80 else 0

                dport = pkt[TCP].dport
                sport = pkt[TCP].sport
                if dport == 80 or sport == 80:
                    has_http = 1
                if dport == 443 or sport == 443:
                    has_https = 1
                if dport == 23 or sport == 23:
                    has_telnet = 1
                if dport == 25 or sport == 25:
                    has_smtp = 1
                if dport == 22 or sport == 22:
                    has_ssh = 1
                if dport == 6667 or sport == 6667:
                    has_irc = 1

            # UDP features
            if UDP in pkt:
                has_udp = 1
                dport = pkt[UDP].dport
                sport = pkt[UDP].sport
                if dport == 53 or sport == 53:
                    has_dns = 1
                if dport == 67 or dport == 68:
                    has_dhcp = 1

            # ARP
            if ARP in pkt:
                has_arp = 1

            # ICMP
            if ICMP in pkt:
                has_icmp = 1

        # ---- CALCULATE FLOW FEATURES ----
        timestamps = sorted(timestamps)

        total_duration = (
            sum(
                [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            )
            if len(timestamps) > 1 else 0
        )

        flow_duration = total_duration

        # Inter-arrival times
        iats = [timestamps[j+1] - timestamps[j] for j in range(len(timestamps)-1)]
        iat_mean = np.mean(iats) if iats else 0

        # Packet size stats
        tot_size = sum(pkt_sizes)
        pkt_min = min(pkt_sizes)
        pkt_max = max(pkt_sizes)
        pkt_avg = np.mean(pkt_sizes)
        pkt_std = np.std(pkt_sizes)

        # Header length
        header_len = sum(header_lengths) if header_lengths else 0

        # Rate features
        duration = flow_duration if flow_duration > 0 else 1e-6
        rate = len(window) / duration
        srate = tot_size / duration
        drate = 0  # bidirectional rate, set to 0 for single direction

        # Statistical features
        tot_sum = sum(pkt_sizes)
        number = len(window)

        #Flow ID
        flow_id = f"{window[0][IP].src}-{window[0][IP].dst}-{proto}"

        # Magnitude
        magnitude = math.sqrt(sum([s**2 for s in pkt_sizes])) / number if number > 0 else 0

        # Radius
        mean_size = pkt_avg
        radius = math.sqrt(sum([(s - mean_size)**2 for s in pkt_sizes]) / number) if number > 0 else 0

        # Covariance (size vs IAT)
        if len(iats) > 0 and len(pkt_sizes) > 1:
            min_len = min(len(pkt_sizes[:-1]), len(iats))
            covariance = np.cov(pkt_sizes[:min_len], iats[:min_len])[0][1] if min_len > 1 else 0
        else:
            covariance = 0

        # Variance
        variance = np.var(pkt_sizes) if pkt_sizes else 0

        # Weight
        weight = tot_size / number if number > 0 else 0

        # Duration field (TTL based)
        duration_field = pkt[IP].ttl if IP in window[0] else 64
        
        from datetime import datetime
        
        # 1. Define the Service Map (Add more if needed for your IoT devices!)
        service_map = {
            # Web & Remote Access
            80: 'HTTP', 443: 'HTTPS', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
            22: 'SSH', 23: 'Telnet', 2323: 'Telnet-Alt', 3389: 'RDP',
            # File & Database
            21: 'FTP', 20: 'FTP-Data', 445: 'SMB', 3306: 'MySQL', 5432: 'PostgreSQL',
            # Network Services
            53: 'DNS', 67: 'DHCP', 68: 'DHCP', 123: 'NTP', 161: 'SNMP',
            # IoT Specific
            1883: 'MQTT', 5060: 'SIP', 5900: 'VNC', 6379: 'Redis'
        }

        first_pkt = best_window(window)
        found_services = set()

        # 2. Loop through all 10 packets in the window
        for pkt in window:
            s_port = 0
            d_port = 0
            
            if TCP in pkt:
                s_port = pkt[TCP].sport
                d_port = pkt[TCP].dport
            elif UDP in pkt:
                s_port = pkt[UDP].sport
                d_port = pkt[UDP].dport
            else:
                continue 

            # Apply your Rule: Dest Map -> Source Map -> Fallback
            if d_port in service_map:
                found_services.add(service_map[d_port])
            elif s_port in service_map:
                found_services.add(service_map[s_port])
            else:
                found_services.add(f"Port {d_port}")

        # 3. Join the unique results into a clean string
        service_display = ", ".join(sorted(list(found_services)))

        # 4. Identity Info
        src_ip = first_pkt[IP].src if IP in first_pkt else "0.0.0.0"
        dst_ip = first_pkt[IP].dst if IP in first_pkt else "0.0.0.0"
        src_mac = first_pkt[Ether].src if Ether in first_pkt else "00:00:00:00:00:00"
        dst_mac = first_pkt[Ether].dst if Ether in first_pkt else "00:00:00:00:00:00"
        
        proto_map = {1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP', 58: 'ICMPv6'}
        proto_name = proto_map.get(proto, str(proto))
        timestamp_str = datetime.fromtimestamp(timestamps[0]).strftime('%Y-%m-%d %H:%M:%S')

        record = {
            'Flow_ID': flow_id,
            'Timestamp': timestamp_str,
            'first_seen': timestamp_str,
            'last_seen': datetime.fromtimestamp(timestamps[-1]).strftime('%Y-%m-%d %H:%M:%S'),
            'Src_IP': src_ip,
            'Dst_IP': dst_ip,
            'Src_MAC': src_mac,
            'Dst_MAC': dst_mac,
            'Protocol_Name': proto_name,
            'Service': service_display,

            #47 CIC-IoT2023 Features
            'flow_duration': flow_duration,
            'Header_Length': header_len,
            'Protocol Type': proto,
            'Duration': duration_field,
            'Rate': rate,
            'Srate': srate,
            'Drate': drate,
            'fin_flag_number': fin_flags,
            'syn_flag_number': syn_flags,
            'rst_flag_number': rst_flags,
            'psh_flag_number': psh_flags,
            'ack_flag_number': ack_flags,
            'ece_flag_number': ece_flags,
            'cwr_flag_number': cwr_flags,
            'ack_count': ack_flags,
            'syn_count': syn_flags,
            'fin_count': fin_flags,
            'urg_count': urg_flags,
            'rst_count': rst_flags,
            'HTTP': has_http,
            'HTTPS': has_https,
            'DNS': has_dns,
            'Telnet': has_telnet,
            'SMTP': has_smtp,
            'SSH': has_ssh,
            'IRC': has_irc,
            'TCP': has_tcp,
            'UDP': has_udp,
            'DHCP': has_dhcp,
            'ARP': has_arp,
            'ICMP': has_icmp,
            'IPv': has_ipv,
            'LLC': has_llc,
            'Tot sum': tot_sum,
            'Min': pkt_min,
            'Max': pkt_max,
            'AVG': pkt_avg,
            'Std': pkt_std,
            'Tot size': tot_size,
            'IAT': iat_mean,
            'Number': number,
            'Magnitue': magnitude,
            'Radius': radius,
            'Covariance': covariance,
            'Variance': variance,
            'Weight': weight
        }

        return record

    except Exception as e:
        print(f"Error extracting features: {e}")
        return None



def pcap_to_csv(pcap_file, display_csv, model_csv, window_size=10):
    """
    Saves two separate CSVs: 
    1. display_records.csv: Everything the UI needs (Identity + Stats)
    2. prediction_ready.csv: Strictly the 46 features for XGBoost
    """
    df = extract_features_from_pcap(pcap_file, window_size)

    if df.empty:
        print("No features extracted!")
        return None

    # 1. DEFINE FRONT-END COLUMNS
    # Adding 'Tot size' (Bytes), 'Number' (Packets), and 'flow_duration' (Time)
    display_columns = [
        'Flow_ID','Timestamp', 'Src_IP', 'Dst_IP', 'Src_MAC', 'Dst_MAC', 
        'Protocol_Name', 'Service', 'Tot size', 'Number', 'flow_duration'
    ]
    
    # 2. DEFINE ML FEATURES (Must match your model training exactly)
    ml_features = [
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

    # --- SAVE FRONT-END FILE ---
    df_display = df[display_columns]
    df_display.to_csv(display_csv, index=False)
    print(f"Front-end CSV saved (Bytes/Packets included): {display_csv}")

    # --- SAVE PREDICTION FILE ---
    df_model = df[ml_features]
    df_model.fillna(0, inplace=True)
    df_model.to_csv(model_csv, index=False)
    print(f"Model-ready CSV saved: {model_csv}")

    return df_display, df_model

