# config/toolkit/modules/network_analysis/capture.py
import pydivert
from scapy.all import sniff, Raw
from scapy.layers.inet import IP, TCP, UDP
import dpkt
import threading
import time
from datetime import datetime
from collections import defaultdict
from .utils import packet_to_dict
from django.conf import settings
import os


class NetworkCapture:
    def __init__(self):
        self.capture_active = False
        self.capture_thread = None
        self.packets = []
        self.stats = {
            'total_packets': 0,
            'protocols': defaultdict(int),
            'source_ips': defaultdict(int),
            'dest_ips': defaultdict(int),
            'ports': defaultdict(int),
            'start_time': None,
            'end_time': None
        }
        self.rules = []
        self.alerts = []
        self.capture_file = os.path.join(settings.BASE_DIR, 'network_capture.pcap')

    def start_capture(self, interface=None, filter_rule=None, timeout=60):
        """Start packet capture"""
        if self.capture_active:
            return False

        self.capture_active = True
        self.stats['start_time'] = datetime.now()

        def capture_loop():
            try:
                # Using pydivert for Windows packet capture
                with pydivert.WinDivert(filter_rule or "true") as w:
                    while self.capture_active:
                        packet = w.recv()
                        self.process_packet(packet)
                        w.send(packet)
            except Exception as e:
                print(f"Capture error: {e}")
            finally:
                self.capture_active = False
                self.stats['end_time'] = datetime.now()

        self.capture_thread = threading.Thread(target=capture_loop)
        self.capture_thread.start()
        return True

    def stop_capture(self):
        """Stop packet capture"""
        self.capture_active = False
        if self.capture_thread:
            self.capture_thread.join()
        self.save_to_pcap()

    def process_packet(self, packet):
        """Process captured packet"""
        try:
            # Convert to Scapy packet for analysis
            scapy_pkt = IP(packet.raw)
            pkt_dict = packet_to_dict(scapy_pkt)

            # Add raw payload if it exists
            if Raw in scapy_pkt:
                pkt_dict['payload'] = str(scapy_pkt[Raw].load)

            self.packets.append(pkt_dict)
            self.update_stats(pkt_dict)
            self.check_rules(pkt_dict)
        except Exception as e:
            print(f"Packet processing error: {e}")

    def update_stats(self, packet):
        """Update statistics with new packet"""
        self.stats['total_packets'] += 1
        self.stats['protocols'][packet.get('protocol')] += 1

        if 'src_ip' in packet:
            self.stats['source_ips'][packet['src_ip']] += 1
        if 'dst_ip' in packet:
            self.stats['dest_ips'][packet['dst_ip']] += 1
        if 'src_port' in packet:
            self.stats['ports'][packet['src_port']] += 1
        if 'dst_port' in packet:
            self.stats['ports'][packet['dst_port']] += 1

    def check_rules(self, packet):
        """Check packet against defined rules"""
        for rule in self.rules:
            if rule.matches(packet):
                alert = {
                    'timestamp': datetime.now().isoformat(),
                    'rule_id': rule.id,
                    'rule_name': rule.name,
                    'packet': packet,
                    'severity': rule.severity
                }
                self.alerts.append(alert)

    def save_to_pcap(self):
        """Save captured packets to PCAP file"""
        try:
            with open(self.capture_file, 'wb') as f:
                pcap_writer = dpkt.pcap.Writer(f)
                for pkt in self.packets:
                    if 'raw' in pkt:
                        pcap_writer.writepkt(pkt['raw'], pkt.get('timestamp', 0))
        except Exception as e:
            print(f"Error saving PCAP: {e}")

    def clear_capture(self):
        """Clear captured data"""
        self.packets = []
        self.alerts = []
        self.stats = {
            'total_packets': 0,
            'protocols': defaultdict(int),
            'source_ips': defaultdict(int),
            'dest_ips': defaultdict(int),
            'ports': defaultdict(int),
            'start_time': None,
            'end_time': None
        }
