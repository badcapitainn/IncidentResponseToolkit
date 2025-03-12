from scapy.all import sniff, IP, TCP, UDP
from logger import log_info


def packet_callback(packet):
    if packet.haslayer(IP):
        source = packet[IP].src
        destination = packet[IP].dst
        protocol = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "OTHER"

        log_info(f"Packet Captured: {source} -> {destination} | Protocol: {protocol}")


# Start packet sniffing
def start_capture(interface="eth0"):
    log_info(f"Starting packet capture on {interface}...")
    sniff(iface=interface, prn=packet_callback, store=False)


if __name__ == "__main__":
    start_capture()
