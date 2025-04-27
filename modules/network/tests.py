# modules/network/tests.py
import unittest
from scapy.all import IP, TCP
from .analyzer import NetworkAnalyzer
from .rules import SIGNATURE_RULES, HEURISTIC_RULES


class TestNetworkAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = NetworkAnalyzer(alert_callback=None)

    def test_port_scan_detection(self):
        # Create a series of SYN packets to different ports
        packets = []
        for port in range(80, 90):  # Scan ports 80-89
            packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(flags="S", dport=port)
            packets.append(packet)

        # Process packets
        for packet in packets:
            self.analyzer._process_packet(packet)

        # Check for port scan alert
        alerts = self.analyzer.get_alerts()
        port_scan_alerts = [a for a in alerts if a['type'] == 'port_scan']
        self.assertGreater(len(port_scan_alerts), 0, "Port scan not detected")

    def test_malicious_ip_detection(self):
        # Create a packet from a known malicious IP
        malicious_ip = SIGNATURE_RULES['malicious_ips']['ips'][0]
        packet = IP(src=malicious_ip, dst="192.168.1.2") / TCP(dport=80)

        # Process packet
        self.analyzer._process_packet(packet)

        # Check for malicious IP alert
        alerts = self.analyzer.get_alerts()
        ip_alerts = [a for a in alerts if a['type'] == 'malicious_ip']
        self.assertGreater(len(ip_alerts), 0, "Malicious IP not detected")

    def test_http_attack_detection(self):
        # Create a suspicious HTTP request
        from scapy.layers import http
        http_request = http.HTTPRequest(
            Method=b"GET",
            Path=b"/index.php?q=1' UNION SELECT * FROM users--",
            Host=b"example.com"
        )
        packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(dport=80) / http_request

        # Process packet
        self.analyzer._process_packet(packet)

        # Check for HTTP attack alert
        alerts = self.analyzer.get_alerts()
        http_alerts = [a for a in alerts if a['type'] == 'http_attack']
        self.assertGreater(len(http_alerts), 0, "HTTP attack not detected")


if __name__ == '__main__':
    unittest.main()