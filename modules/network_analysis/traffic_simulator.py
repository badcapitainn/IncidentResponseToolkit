from scapy.all import send, Raw
from scapy.layers.inet import IP, TCP
import random
import time
from log_handler import log_event

# Normal and malicious payloads
NORMAL_PAYLOADS = [
    "Hello, this is a normal request.",
    "User login request.",
    "GET /index.html HTTP/1.1",
    "Ping request to server.",
]

MALICIOUS_PAYLOADS = [
    "malware.exe",
    "exploit attack detected!",
    "sql_injection' OR '1'='1'; --",
    "DDoS flood incoming!"
]


def send_traffic(interface="Wi-Fi", num_packets=50, malicious_chance=0.2):
    """ Generates normal and malicious network traffic and logs it. """
    log_event("[+] Starting network traffic simulation...", "info")

    for _ in range(num_packets):
        src_ip = f"192.168.1.{random.randint(2, 254)}"
        dst_ip = "192.168.1.1"

        is_malicious = random.random() < malicious_chance
        payload = random.choice(MALICIOUS_PAYLOADS if is_malicious else NORMAL_PAYLOADS)

        # Create a network packet
        packet = IP(src=src_ip, dst=dst_ip) / TCP(dport=80, sport=random.randint(1024, 65535)) / Raw(load=payload)
        send(packet, iface=interface, verbose=False)

        # Log the packet
        if is_malicious:
            log_event(f"[MALICIOUS] Sent packet: {payload}", "warning")
        else:
            log_event(f"[NORMAL] Sent packet: {payload}", "info")

        time.sleep(random.uniform(0.5, 2))  # Random delay to mimic real traffic


if __name__ == "__main__":
    send_traffic()
