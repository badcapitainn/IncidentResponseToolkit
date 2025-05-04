# config/toolkit/modules/network_analysis/utils.py
from scapy.layers.inet import IP, TCP, UDP
from datetime import datetime


def packet_to_dict(packet):
    """Convert Scapy packet to dictionary"""
    pkt_dict = {
        'timestamp': datetime.now().isoformat(),
        'size': len(packet)
    }

    if IP in packet:
        pkt_dict['src_ip'] = packet[IP].src
        pkt_dict['dst_ip'] = packet[IP].dst
        pkt_dict['protocol'] = packet[IP].proto

        if TCP in packet:
            pkt_dict['src_port'] = packet[TCP].sport
            pkt_dict['dst_port'] = packet[TCP].dport
            pkt_dict['protocol_name'] = 'TCP'
            pkt_dict['flags'] = packet[TCP].flags
        elif UDP in packet:
            pkt_dict['src_port'] = packet[UDP].sport
            pkt_dict['dst_port'] = packet[UDP].dport
            pkt_dict['protocol_name'] = 'UDP'
        else:
            pkt_dict['protocol_name'] = 'Other'

    return pkt_dict


def format_size(size_bytes):
    """Format size in human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} TB"


def format_timestamp(timestamp):
    """Format timestamp to readable format"""
    if isinstance(timestamp, (int, float)):
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    return timestamp

