import scapy.all as scapy
from scapy.layers import http
from scapy.layers.inet import IP, TCP, UDP, ICMP
import time
from collections import defaultdict
import ipaddress
from datetime import datetime
from django.utils.timezone import now
import threading
import queue
import re

from toolkit.models import NetworkTraffic, NetworkAlert, NetworkRule

from .rules import STANDARD_RULES, get_all_rules


class NetworkAnalyzer:
    def __init__(self, interface=None, packet_count=0, timeout=60):
        self.interface = interface or self.get_default_interface()
        self.packet_count = packet_count  # 0 for unlimited
        self.timeout = timeout
        self.rules = get_all_rules()
        self.packet_queue = queue.Queue()
        self.analysis_thread = None
        self.capture_thread = None
        self.stop_event = threading.Event()

        # Tracking for stateful analysis
        self.port_scan_tracker = defaultdict(lambda: defaultdict(set))
        self.packet_count_tracker = defaultdict(int)
        self.last_reset_time = time.time()

    @staticmethod
    def get_default_interface():
        """Get the default network interface"""
        interfaces = scapy.get_if_list()
        return interfaces[0] if interfaces else 'eth0'

    def start_capture(self):
        """Start packet capture in a separate thread"""
        if self.capture_thread and self.capture_thread.is_alive():
            return False

        self.stop_event.clear()
        self.capture_thread = threading.Thread(
            target=self._capture_packets,
            daemon=True
        )
        self.capture_thread.start()

        self.analysis_thread = threading.Thread(
            target=self._analyze_packets,
            daemon=True
        )
        self.analysis_thread.start()

        return True

    def stop_capture(self):
        """Stop packet capture"""
        self.stop_event.set()
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
        if self.analysis_thread:
            self.analysis_thread.join(timeout=2)

    def _capture_packets(self):
        """Internal method to capture packets using scapy"""
        scapy.sniff(
            iface=self.interface,
            prn=self._process_packet,
            store=False,
            count=self.packet_count,
            timeout=self.timeout,
            stop_filter=lambda _: self.stop_event.is_set()
        )

    def _process_packet(self, packet):
        """Process each captured packet and add to queue"""
        try:
            self.packet_queue.put(packet)
        except Exception as e:
            print(f"Error processing packet: {e}")

    def _analyze_packets(self):
        """Analyze packets from the queue"""
        while not self.stop_event.is_set():
            try:
                packet = self.packet_queue.get(timeout=1)
                if packet:
                    self._analyze_packet(packet)
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Error analyzing packet: {e}")

    def _analyze_packet(self, packet):
        """Analyze a single packet against all rules"""
        packet_info = self._extract_packet_info(packet)
        if not packet_info:
            return

        # Check for port scanning
        self._check_port_scan(packet_info)

        # Check for packet flood
        self._check_packet_flood(packet_info)

        # Check all other rules
        for rule in self.rules:
            try:
                if self._matches_rule(packet_info, rule):
                    self._handle_rule_match(packet_info, rule)
            except Exception as e:
                print(f"Error applying rule {rule.get('name')}: {e}")

        # Save packet to database
        self._save_packet(packet_info)

    def _extract_packet_info(self, packet):
        """Extract relevant information from packet"""
        packet_info = {
            'timestamp': datetime.fromtimestamp(packet.time),
            'source_ip': None,
            'destination_ip': None,
            'protocol': None,
            'port': None,
            'flags': None,
            'size': len(packet),
            'payload': None,
            'is_malicious': False,
            'threat_type': None,
            'matched_rule': None
        }

        # IP layer
        if IP in packet:
            packet_info['source_ip'] = packet[IP].src
            packet_info['destination_ip'] = packet[IP].dst

        # TCP layer
        if TCP in packet:
            packet_info['protocol'] = 'TCP'
            packet_info['port'] = packet[TCP].dport
            packet_info['flags'] = self._get_tcp_flags(packet[TCP])

        # UDP layer
        elif UDP in packet:
            packet_info['protocol'] = 'UDP'
            packet_info['port'] = packet[UDP].dport

        # ICMP layer
        elif ICMP in packet:
            packet_info['protocol'] = 'ICMP'

        # HTTP layer
        if packet.haslayer(http.HTTPRequest):
            http_layer = packet.getlayer(http.HTTPRequest)
            packet_info['payload'] = str(http_layer.fields)

            # Extract User-Agent if present
            if 'User-Agent' in http_layer.fields:
                packet_info['user_agent'] = http_layer.fields['User-Agent']

            # Extract URI if present
            if 'Path' in http_layer.fields:
                packet_info['uri'] = http_layer.fields['Path']

        elif packet.haslayer(http.HTTPResponse):
            http_layer = packet.getlayer(http.HTTPResponse)
            packet_info['payload'] = str(http_layer.fields)

        return packet_info

    def _get_tcp_flags(self, tcp_packet):
        """Get TCP flags as string"""
        flags = []
        if tcp_packet.flags & 0x01: flags.append("FIN")
        if tcp_packet.flags & 0x02: flags.append("SYN")
        if tcp_packet.flags & 0x04: flags.append("RST")
        if tcp_packet.flags & 0x08: flags.append("PSH")
        if tcp_packet.flags & 0x10: flags.append("ACK")
        if tcp_packet.flags & 0x20: flags.append("URG")
        if tcp_packet.flags & 0x40: flags.append("ECE")
        if tcp_packet.flags & 0x80: flags.append("CWR")
        return "+".join(flags) if flags else None

    def _matches_rule(self, packet_info, rule):
        """Check if packet matches a specific rule"""
        if rule['type'] == 'MALICIOUS_IP':
            return self._check_malicious_ip(packet_info, rule)
        elif rule['type'] == 'EXPLOIT_PORTS':
            return self._check_exploit_ports(packet_info, rule)
        elif rule['type'] == 'TCP_FLAGS':
            return self._check_tcp_flags(packet_info, rule)
        elif rule['type'] == 'DNS_TUNNELING':
            return self._check_dns_tunneling(packet_info, rule)
        elif rule['type'] == 'HTTP_USER_AGENT':
            return self._check_http_user_agent(packet_info, rule)
        elif rule['type'] == 'HTTP_POWERSHELL':
            return self._check_http_powershell(packet_info, rule)
        elif rule['type'] == 'SUSPICIOUS_EXTENSIONS':
            return self._check_suspicious_extensions(packet_info, rule)
        elif rule['type'] == 'HTTP_METHODS':
            return self._check_http_methods(packet_info, rule)
        return False

    def _check_malicious_ip(self, packet_info, rule):
        """Check if IP is in malicious list"""
        src_ip = packet_info.get('source_ip')
        dst_ip = packet_info.get('destination_ip')

        if not src_ip or not dst_ip:
            return False

        for ip_network in rule.get('ips', []):
            try:
                network = ipaddress.ip_network(ip_network)
                if (ipaddress.ip_address(src_ip) in network or
                        ipaddress.ip_address(dst_ip) in network):
                    return True
            except ValueError:
                continue
        return False

    def _check_exploit_ports(self, packet_info, rule):
        """Check if port is in commonly exploited list"""
        port = packet_info.get('port')
        return port and port in rule.get('ports', [])

    def _check_tcp_flags(self, packet_info, rule):
        """Check for suspicious TCP flag combinations"""
        flags = packet_info.get('flags')
        return flags and flags in rule.get('flags', [])

    def _check_dns_tunneling(self, packet_info, rule):
        """Check for DNS tunneling attempts"""
        if packet_info.get('protocol') != 'UDP' or packet_info.get('port') != 53:
            return False
        return packet_info.get('size', 0) > rule.get('size_threshold', 512)

    def _check_http_user_agent(self, packet_info, rule):
        """Check for suspicious HTTP User-Agents"""
        user_agent = packet_info.get('user_agent', '').lower()
        if not user_agent:
            return False

        for pattern in rule.get('patterns', []):
            if pattern.lower() in user_agent:
                return True
        return False

    def _check_http_powershell(self, packet_info, rule):
        """Check for PowerShell commands in HTTP traffic"""
        payload = packet_info.get('payload', '').lower()
        if not payload:
            return False

        for pattern in rule.get('patterns', []):
            if pattern.lower() in payload:
                return True
        return False

    def _check_suspicious_extensions(self, packet_info, rule):
        """Check for requests to suspicious file extensions"""
        uri = packet_info.get('uri', '')
        if not uri:
            return False

        for ext in rule.get('extensions', []):
            if uri.lower().endswith(ext.lower()):
                return True
        return False

    def _check_http_methods(self, packet_info, rule):
        """Check for unusual HTTP methods"""
        payload = packet_info.get('payload', '')
        if not payload:
            return False

        # Extract HTTP method from payload
        match = re.search(r"'Method':\s*'([A-Z]+)'", payload)
        if not match:
            return False

        method = match.group(1)
        return method in rule.get('methods', [])

    def _check_port_scan(self, packet_info):
        """Check for port scanning behavior"""
        if not packet_info.get('source_ip') or not packet_info.get('port'):
            return

        current_time = time.time()
        if current_time - self.last_reset_time > 60:  # Reset every minute
            self.port_scan_tracker.clear()
            self.last_reset_time = current_time

        src_ip = packet_info['source_ip']
        port = packet_info['port']

        self.port_scan_tracker[src_ip]['ports'].add(port)

        # Check if this IP has scanned too many ports
        port_scan_rule = next(
            (r for r in self.rules if r['type'] == 'PORT_SCAN'),
            None
        )

        if port_scan_rule:
            threshold = port_scan_rule.get('threshold', 5)
            if len(self.port_scan_tracker[src_ip]['ports']) >= threshold:
                packet_info['is_malicious'] = True
                packet_info['threat_type'] = 'Port Scan'
                packet_info['matched_rule'] = port_scan_rule['name']

                # Create alert
                self._create_alert(
                    packet_info,
                    port_scan_rule,
                    f"Port scanning detected from {src_ip}. Scanned ports: {len(self.port_scan_tracker[src_ip]['ports'])}"
                )

    def _check_packet_flood(self, packet_info):
        """Check for packet flood (DoS attempt)"""
        if not packet_info.get('source_ip'):
            return

        current_time = time.time()
        if current_time - self.last_reset_time > 1:  # Reset every second
            self.packet_count_tracker.clear()
            self.last_reset_time = current_time

        src_ip = packet_info['source_ip']
        self.packet_count_tracker[src_ip] += 1

        # Check if this IP is flooding packets
        flood_rule = next(
            (r for r in self.rules if r['type'] == 'PACKET_FLOOD'),
            None
        )

        if flood_rule:
            threshold = flood_rule.get('threshold', 1000)
            if self.packet_count_tracker[src_ip] >= threshold:
                packet_info['is_malicious'] = True
                packet_info['threat_type'] = 'Packet Flood'
                packet_info['matched_rule'] = flood_rule['name']

                # Create alert
                self._create_alert(
                    packet_info,
                    flood_rule,
                    f"Packet flood detected from {src_ip}. Packets per second: {self.packet_count_tracker[src_ip]}"
                )

    def _handle_rule_match(self, packet_info, rule):
        """Handle a rule match (create alert, block, etc.)"""
        packet_info['is_malicious'] = True
        packet_info['threat_type'] = rule['name']
        packet_info['matched_rule'] = rule['name']

        if rule['action'] == 'ALERT':
            self._create_alert(
                packet_info,
                rule,
                f"Rule matched: {rule['name']}. Threat type: {rule['type']}"
            )
        elif rule['action'] == 'BLOCK':
            # In a real implementation, you would add iptables rule here
            self._create_alert(
                packet_info,
                rule,
                f"Blocked traffic matching rule: {rule['name']}"
            )

    def _create_alert(self, packet_info, rule, description):
        """Create a network alert in the database"""
        try:
            # First save the packet if not already saved
            packet = self._save_packet(packet_info)

            # Get or create the rule in database
            db_rule, _ = NetworkRule.objects.get_or_create(
                name=rule['name'],
                defaults={
                    'description': rule.get('description', ''),
                    'rule_type': rule['type'],
                    'pattern': str(rule),
                    'action': rule['action'],
                    'severity': rule.get('severity', 'medium'),
                    'created_by_id': 1  # Default admin user
                }
            )

            # Create the alert
            NetworkAlert.objects.create(
                traffic=packet,
                rule=db_rule,
                description=description,
                severity=rule.get('severity', 'medium'),
                status='open'
            )
        except Exception as e:
            print(f"Error creating alert: {e}")

    def _save_packet(self, packet_info):
        """Save packet information to database"""
        try:
            packet = NetworkTraffic.objects.create(
                timestamp=packet_info['timestamp'],
                source_ip=packet_info.get('source_ip', ''),
                destination_ip=packet_info.get('destination_ip', ''),
                protocol=packet_info.get('protocol', ''),
                port=packet_info.get('port'),
                packet_size=packet_info.get('size', 0),
                flags=packet_info.get('flags'),
                payload=packet_info.get('payload'),
                is_malicious=packet_info.get('is_malicious', False),
                threat_type=packet_info.get('threat_type'),
                matched_rule=packet_info.get('matched_rule')
            )
            return packet
        except Exception as e:
            print(f"Error saving packet: {e}")
            return None
