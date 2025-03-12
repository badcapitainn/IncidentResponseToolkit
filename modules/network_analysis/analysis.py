from scapy.all import IP, TCP
import re
from logger import log_alert, log_info

# Known threats
malicious_ips = ["192.168.1.100", "10.0.0.50"]
sql_injection_patterns = [r"UNION.*SELECT", r"DROP TABLE", r"INSERT INTO"]


def detect_anomalies(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        # Detect malicious IPs
        if ip_dst in malicious_ips:
            log_alert(f"Suspicious connection detected: {ip_src} -> {ip_dst}")
            return

        # Detect SQL injection patterns in payload
        if packet.haslayer(TCP) and packet[TCP].payload:
            payload = str(packet[TCP].payload)
            for pattern in sql_injection_patterns:
                if re.search(pattern, payload, re.IGNORECASE):
                    log_alert(f"Possible SQL Injection from {ip_src} to {ip_dst}")
                    return

        log_info(f"Packet {ip_src} -> {ip_dst} analyzed, no anomalies found.")
