from scapy.all import send, IP, TCP
from logger import log_info


def simulate_legitimate_traffic():
    log_info("Simulating normal traffic...")
    send(IP(src="192.168.1.10", dst="8.8.8.8") / TCP(dport=80), count=5)


def simulate_attack():
    log_info("Simulating attack traffic...")
    send(IP(src="192.168.1.200", dst="192.168.1.100") / TCP(dport=443), count=20)


if __name__ == "__main__":
    simulate_legitimate_traffic()
    simulate_attack()
