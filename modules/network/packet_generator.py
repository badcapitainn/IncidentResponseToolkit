# config/toolkit/modules/network_analysis/packet_generator.py
import random
import socket
import time
import dpkt


class PacketGenerator:
    @staticmethod
    def generate_pcap_file(file_path, packet_count=100):
        """Generate a PCAP file with random packets including attacks"""
        with open(file_path, 'wb') as f:
            pcap_writer = dpkt.pcap.Writer(f)

            # Generate normal background traffic (70%)
            for _ in range(int(packet_count * 0.7)):
                timestamp = time.time()
                packet_type = random.choice(['tcp', 'udp', 'http', 'dns'])  # Removed icmp for now
                packet = PacketGenerator._create_normal_packet(packet_type)
                if packet:  # Only write if packet was created
                    pcap_writer.writepkt(packet, timestamp)

            # Generate attack traffic (30%)
            for _ in range(int(packet_count * 0.3)):
                timestamp = time.time()
                attack_type = random.choice([
                    'port_scan', 'ddos', 'brute_force',
                    'malware_c2', 'sql_injection', 'xss'
                ])
                packet = PacketGenerator._create_attack_packet(attack_type)
                if packet:  # Only write if packet was created
                    pcap_writer.writepkt(packet, timestamp)

    @staticmethod
    def _create_normal_packet(packet_type):
        """Generate normal network traffic"""
        try:
            if packet_type == 'tcp':
                return PacketGenerator._create_random_tcp_packet()
            elif packet_type == 'udp':
                return PacketGenerator._create_random_udp_packet()
            elif packet_type == 'http':
                return PacketGenerator._create_http_packet()
            elif packet_type == 'dns':
                return PacketGenerator._create_dns_packet()
        except Exception as e:
            print(f"Error creating {packet_type} packet: {e}")
            return None

    @staticmethod
    def _create_attack_packet(attack_type):
        """Generate malicious network traffic"""
        try:
            if attack_type == 'port_scan':
                return PacketGenerator._create_port_scan_packet()
            elif attack_type == 'ddos':
                return PacketGenerator._create_ddos_packet()
            elif attack_type == 'brute_force':
                return PacketGenerator._create_brute_force_packet()
            elif attack_type == 'malware_c2':
                return PacketGenerator._create_malware_c2_packet()
            elif attack_type == 'sql_injection':
                return PacketGenerator._create_sql_injection_packet()
            elif attack_type == 'xss':
                return PacketGenerator._create_xss_packet()
        except Exception as e:
            print(f"Error creating {attack_type} attack packet: {e}")
            return None

    # --- Normal Packet Generators ---
    @staticmethod
    def _create_random_tcp_packet():
        eth = dpkt.ethernet.Ethernet()
        eth.src = PacketGenerator._random_mac()
        eth.dst = PacketGenerator._random_mac()

        ip = dpkt.ip.IP()
        ip.src = socket.inet_aton(PacketGenerator._random_ip())
        ip.dst = socket.inet_aton(PacketGenerator._random_ip())
        ip.p = dpkt.ip.IP_PROTO_TCP

        tcp = dpkt.tcp.TCP()
        tcp.sport = random.randint(1024, 65535)
        tcp.dport = random.choice([80, 443, 22, 3389, 8080, 3306])
        tcp.seq = random.randint(0, 4294967295)
        tcp.ack = random.randint(0, 4294967295)
        tcp.flags = random.choice([dpkt.tcp.TH_ACK, dpkt.tcp.TH_PUSH])

        ip.data = tcp
        eth.data = ip
        return eth.pack()

    @staticmethod
    def _create_random_udp_packet():
        eth = dpkt.ethernet.Ethernet()
        eth.src = PacketGenerator._random_mac()
        eth.dst = PacketGenerator._random_mac()

        ip = dpkt.ip.IP()
        ip.src = socket.inet_aton(PacketGenerator._random_ip())
        ip.dst = socket.inet_aton(PacketGenerator._random_ip())
        ip.p = dpkt.ip.IP_PROTO_UDP

        udp = dpkt.udp.UDP()
        udp.sport = random.randint(1024, 65535)
        udp.dport = random.choice([53, 123, 161, 500, 4500])

        ip.data = udp
        eth.data = ip
        return eth.pack()

    @staticmethod
    def _create_dns_packet():
        eth = dpkt.ethernet.Ethernet()
        eth.src = PacketGenerator._random_mac()
        eth.dst = PacketGenerator._random_mac()

        ip = dpkt.ip.IP()
        ip.src = socket.inet_aton(PacketGenerator._random_ip())
        ip.dst = socket.inet_aton('8.8.8.8')  # Google DNS
        ip.p = dpkt.ip.IP_PROTO_UDP

        udp = dpkt.udp.UDP()
        udp.sport = random.randint(1024, 65535)
        udp.dport = 53

        # Create DNS payload
        dns = dpkt.dns.DNS()
        dns.qd = [dpkt.dns.DNS.Q()]
        dns.qd[0].name = random.choice(['google.com', 'example.com', 'test.com']) + '.'
        dns.qd[0].type = dpkt.dns.DNS_A
        dns.qd[0].cls = dpkt.dns.DNS_IN

        udp.data = dns
        ip.data = udp
        eth.data = ip
        return eth.pack()

    @staticmethod
    def _create_http_packet():
        eth = dpkt.ethernet.Ethernet()
        eth.src = PacketGenerator._random_mac()
        eth.dst = PacketGenerator._random_mac()

        ip = dpkt.ip.IP()
        ip.src = socket.inet_aton(PacketGenerator._random_ip())
        ip.dst = socket.inet_aton(PacketGenerator._random_ip())
        ip.p = dpkt.ip.IP_PROTO_TCP

        tcp = dpkt.tcp.TCP()
        tcp.sport = random.randint(1024, 65535)
        tcp.dport = 80
        tcp.seq = random.randint(0, 4294967295)

        # Add HTTP data
        http_request = (
            f"GET /{random.choice(['index.html', 'test.php', 'api/data'])} HTTP/1.1\r\n"
            f"Host: example.com\r\n"
            f"User-Agent: TestClient/1.0\r\n"
            f"Accept: text/html\r\n\r\n"
        )
        tcp.data = http_request.encode()

        ip.data = tcp
        eth.data = ip
        return eth.pack()

    # --- Attack Packet Generators ---
    @staticmethod
    def _create_port_scan_packet():
        eth = dpkt.ethernet.Ethernet()
        eth.src = PacketGenerator._random_mac()
        eth.dst = PacketGenerator._random_mac()

        ip = dpkt.ip.IP()
        ip.src = socket.inet_aton(PacketGenerator._random_ip())
        ip.dst = socket.inet_aton('192.168.1.1')  # Target IP
        ip.p = dpkt.ip.IP_PROTO_TCP

        tcp = dpkt.tcp.TCP()
        tcp.sport = random.randint(1024, 65535)
        tcp.dport = random.choice([21, 22, 23, 25, 80, 443, 3389, 8080])  # Common ports
        tcp.flags = dpkt.tcp.TH_SYN  # SYN scan
        tcp.seq = random.randint(0, 4294967295)

        ip.data = tcp
        eth.data = ip
        return eth.pack()

    @staticmethod
    def _create_ddos_packet():
        eth = dpkt.ethernet.Ethernet()
        eth.src = PacketGenerator._random_mac()
        eth.dst = PacketGenerator._random_mac()

        ip = dpkt.ip.IP()
        ip.src = socket.inet_aton(PacketGenerator._random_ip())
        ip.dst = socket.inet_aton('10.0.0.1')  # Victim IP
        ip.p = dpkt.ip.IP_PROTO_TCP

        tcp = dpkt.tcp.TCP()
        tcp.sport = random.randint(1024, 65535)
        tcp.dport = 80  # HTTP
        tcp.flags = dpkt.tcp.TH_SYN  # SYN flood
        tcp.seq = random.randint(0, 4294967295)

        ip.data = tcp
        eth.data = ip
        return eth.pack()

    @staticmethod
    def _create_brute_force_packet():
        eth = dpkt.ethernet.Ethernet()
        eth.src = PacketGenerator._random_mac()
        eth.dst = PacketGenerator._random_mac()

        ip = dpkt.ip.IP()
        ip.src = socket.inet_aton(PacketGenerator._random_ip())
        ip.dst = socket.inet_aton('192.168.1.100')  # Target server
        ip.p = dpkt.ip.IP_PROTO_TCP

        tcp = dpkt.tcp.TCP()
        tcp.sport = random.randint(1024, 65535)
        tcp.dport = 22  # SSH
        tcp.flags = dpkt.tcp.TH_ACK

        # SSH brute force attempt
        payload = (
            "SSH-2.0-OpenSSH_7.6p1\r\n"
            f"User: {random.choice(['admin', 'root', 'user', 'test'])}\r\n"
            f"Pass: {random.choice(['password', '123456', 'admin', 'qwerty'])}\r\n"
        )

        tcp.data = payload.encode()
        ip.data = tcp
        eth.data = ip
        return eth.pack()

    @staticmethod
    def _create_malware_c2_packet():
        eth = dpkt.ethernet.Ethernet()
        eth.src = PacketGenerator._random_mac()
        eth.dst = PacketGenerator._random_mac()

        ip = dpkt.ip.IP()
        ip.src = socket.inet_aton('192.168.1.50')  # Infected host
        ip.dst = socket.inet_aton('45.67.89.123')  # C2 server
        ip.p = dpkt.ip.IP_PROTO_TCP

        tcp = dpkt.tcp.TCP()
        tcp.sport = random.randint(1024, 65535)
        tcp.dport = 443  # HTTPS
        tcp.flags = dpkt.tcp.TH_ACK

        # Malicious payload (base64 encoded)
        payload = (
            "POST /c2/report HTTP/1.1\r\n"
            "Host: malicious.com\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            f"Cookie: id={random.randint(1000, 9999)}\r\n"
            "Content-Length: 100\r\n\r\n"
            "data=VGhpcyBpcyBhIG1hbGljaW91cyBwYXlsb2FkIQ=="
        )

        tcp.data = payload.encode()
        ip.data = tcp
        eth.data = ip
        return eth.pack()

    @staticmethod
    def _create_sql_injection_packet():
        eth = dpkt.ethernet.Ethernet()
        eth.src = PacketGenerator._random_mac()
        eth.dst = PacketGenerator._random_mac()

        ip = dpkt.ip.IP()
        ip.src = socket.inet_aton(PacketGenerator._random_ip())
        ip.dst = socket.inet_aton('10.0.0.100')  # Web server
        ip.p = dpkt.ip.IP_PROTO_TCP

        tcp = dpkt.tcp.TCP()
        tcp.sport = random.randint(1024, 65535)
        tcp.dport = 80  # HTTP
        tcp.flags = dpkt.tcp.TH_PUSH

        # SQL injection attempt
        payload = (
            "GET /login.php?user=admin'--&pass=anything HTTP/1.1\r\n"
            "Host: vulnerable.com\r\n"
            "User-Agent: Mozilla/5.0\r\n\r\n"
        )

        tcp.data = payload.encode()
        ip.data = tcp
        eth.data = ip
        return eth.pack()

    @staticmethod
    def _create_xss_packet():
        eth = dpkt.ethernet.Ethernet()
        eth.src = PacketGenerator._random_mac()
        eth.dst = PacketGenerator._random_mac()

        ip = dpkt.ip.IP()
        ip.src = socket.inet_aton(PacketGenerator._random_ip())
        ip.dst = socket.inet_aton('10.0.0.100')  # Web server
        ip.p = dpkt.ip.IP_PROTO_TCP

        tcp = dpkt.tcp.TCP()
        tcp.sport = random.randint(1024, 65535)
        tcp.dport = 80  # HTTP
        tcp.flags = dpkt.tcp.TH_PUSH

        # XSS attempt
        payload = (
            "GET /search?q=<script>alert('XSS')</script> HTTP/1.1\r\n"
            "Host: vulnerable.com\r\n"
            "User-Agent: Mozilla/5.0\r\n\r\n"
        )

        tcp.data = payload.encode()
        ip.data = tcp
        eth.data = ip
        return eth.pack()

    # --- Helper Methods ---
    @staticmethod
    def _random_mac():
        return bytes([random.randint(0x00, 0xff) for _ in range(6)])

    @staticmethod
    def _random_ip():
        return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
