from scapy.all import sniff, Raw
from log_handler import log_event


def inspect_packet(packet):
    """ Inspects packets for malicious payloads and logs them. """
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        if b"malware" in payload or b"exploit" in payload or b"sql_injection" in payload:
            log_event(f"Suspicious packet detected: {payload}", "error")


def start_inspection(interface="Wi-Fi", count=50):
    """ Starts deep packet inspection and logs activity. """
    log_event(f"Starting deep packet inspection on {interface}...", "info")
    sniff(iface=interface, prn=inspect_packet, count=count)
