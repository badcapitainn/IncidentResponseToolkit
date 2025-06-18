from scapy.all import sniff, Raw
from scapy.layers.inet import IP, TCP, UDP
from scapy.sendrecv import sendp
# from scapy.supersocket import L3PacketSocket
import dpkt
import threading
import time
# import nfqueue
from datetime import datetime
from collections import defaultdict
from .utils import packet_to_dict
from django.conf import settings
import os
import socket
import struct

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
        self.blocked_ips = set()
        # self.nfqueue_socket = None
        # self.queue_num = 1  # NFQUEUE number

    def start_capture(self, interface=None, filter_rule=None, timeout=60):
        """Start packet capture"""
        if self.capture_active:
            return False

        self.capture_active = True
        self.stats['start_time'] = datetime.now()

        def capture_loop():
            try:
                # Use scapy's sniff function for packet capture
                sniff(iface=interface, 
                      prn=self.process_packet, 
                      store=False,
                      filter=filter_rule,
                      stop_filter=lambda x: not self.capture_active)
            except Exception as e:
                print(f"Capture error: {e}")
            finally:
                self.capture_active = False
                self.stats['end_time'] = datetime.now()

        self.capture_thread = threading.Thread(target=capture_loop)
        self.capture_thread.start()
        return True

    def setup_nfqueue(self):
        """Setup NFQUEUE for packet filtering"""
        def callback(i, payload):
            data = payload.get_data()
            packet = IP(data)
            
            # Process packet before deciding to drop/accept
            self.process_packet(packet)
            
            # Implement your filtering logic here
            if packet[IP].src in self.blocked_ips:
                payload.set_verdict(nfqueue.NF_DROP)
            else:
                payload.set_verdict(nfqueue.NF_ACCEPT)
        
        q = nfqueue.queue()
        q.set_callback(callback)
        q.fast_open(self.queue_num, socket.AF_INET)
        q.set_queue_maxlen(5000)
        
        try:
            while self.capture_active:
                q.process_pending()
        finally:
            q.unbind(socket.AF_INET)
            q.close()

    def process_packet(self, packet):
        """Process captured packet"""
        try:
            pkt_dict = packet_to_dict(packet)

            # Add raw payload if it exists
            if packet.haslayer(Raw):
                pkt_dict['payload'] = str(packet[Raw].load)

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

    def stop_capture(self):
        """Stop packet capture"""
        self.capture_active = False
        if self.capture_thread:
            self.capture_thread.join()
        self.save_to_pcap()