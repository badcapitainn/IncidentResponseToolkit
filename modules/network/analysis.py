# config/toolkit/modules/network_analysis/analysis.py
from collections import defaultdict
import dpkt
import socket
import datetime
from scapy.layers.inet import IP, TCP, UDP
import matplotlib

matplotlib.use('Agg')  # Set the backend to Agg before importing pyplot

import matplotlib.pyplot as plt
from io import BytesIO
import base64
import pandas as pd


class NetworkAnalyzer:
    def __init__(self, capture_file):
        self.capture_file = capture_file
        self.packets = []
        self.stats = {
            'total_packets': 0,  # Add this line to initialize total_packets
            'protocols': defaultdict(int),
            'source_ips': defaultdict(int),
            'dest_ips': defaultdict(int),
            'ports': defaultdict(int),
            'timeline': defaultdict(int),
            'start_time': None,
            'end_time': None
        }

    def load_pcap(self):
        """Load packets from PCAP file"""
        try:
            with open(self.capture_file, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                for ts, buf in pcap:
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                        ip = eth.data

                        packet = {
                            'timestamp': ts,
                            'src_ip': socket.inet_ntoa(ip.src),
                            'dst_ip': socket.inet_ntoa(ip.dst),
                            'protocol': ip.p,
                            'size': len(buf)
                        }

                        if isinstance(ip.data, dpkt.tcp.TCP):
                            packet['src_port'] = ip.data.sport
                            packet['dst_port'] = ip.data.dport
                            packet['protocol_name'] = 'TCP'
                        elif isinstance(ip.data, dpkt.udp.UDP):
                            packet['src_port'] = ip.data.sport
                            packet['dst_port'] = ip.data.dport
                            packet['protocol_name'] = 'UDP'
                        else:
                            packet['protocol_name'] = 'Other'

                        self.packets.append(packet)
                        self.update_stats(packet)

                    except:
                        continue
        except Exception as e:
            print(f"Error loading PCAP: {e}")

    def update_stats(self, packet):
        """Update statistics with packet data"""
        self.stats['total_packets'] += 1  # Increment total packets count

        if not self.stats['start_time'] or packet['timestamp'] < self.stats['start_time']:
            self.stats['start_time'] = packet['timestamp']
        if not self.stats['end_time'] or packet['timestamp'] > self.stats['end_time']:
            self.stats['end_time'] = packet['timestamp']

        self.stats['protocols'][packet['protocol_name']] += 1
        self.stats['source_ips'][packet['src_ip']] += 1
        self.stats['dest_ips'][packet['dst_ip']] += 1

        if 'src_port' in packet:
            self.stats['ports'][packet['src_port']] += 1
        if 'dst_port' in packet:
            self.stats['ports'][packet['dst_port']] += 1

        # Round timestamp to nearest minute for timeline
        minute = datetime.datetime.fromtimestamp(packet['timestamp']).strftime('%Y-%m-%d %H:%M')
        self.stats['timeline'][minute] += 1

    def get_protocol_distribution(self):
        """Return protocol distribution data"""
        return dict(self.stats['protocols'])

    def get_top_ips(self, count=10, type='source'):
        """Return top source or destination IPs"""
        ips = self.stats['source_ips'] if type == 'source' else self.stats['dest_ips']
        return dict(sorted(ips.items(), key=lambda x: x[1], reverse=True)[:count])

    def get_top_ports(self, count=10):
        """Return top ports"""
        return dict(sorted(self.stats['ports'].items(), key=lambda x: x[1], reverse=True)[:count])

    def get_timeline_data(self):
        """Return timeline data for plotting"""
        timeline = sorted(self.stats['timeline'].items())
        if not timeline:
            return [], []
        times, counts = zip(*timeline)
        return times, counts

    def generate_protocol_chart(self):
        """Generate protocol distribution pie chart"""
        protocols = self.get_protocol_distribution()
        if not protocols:
            return None

        plt.figure(figsize=(8, 6))
        plt.pie(protocols.values(), labels=protocols.keys(), autopct='%1.1f%%')
        plt.title('Protocol Distribution')

        buffer = BytesIO()
        plt.savefig(buffer, format='png')
        buffer.seek(0)
        image_base64 = base64.b64encode(buffer.read()).decode('utf-8')
        plt.close()

        return image_base64

    def generate_timeline_chart(self):
        """Generate traffic timeline chart"""
        times, counts = self.get_timeline_data()
        if not times:
            return None

        plt.figure(figsize=(10, 6))
        plt.plot(times, counts, marker='o')
        plt.title('Network Traffic Timeline')
        plt.xlabel('Time')
        plt.ylabel('Packets per minute')
        plt.xticks(rotation=45)
        plt.tight_layout()

        buffer = BytesIO()
        plt.savefig(buffer, format='png')
        buffer.seek(0)
        image_base64 = base64.b64encode(buffer.read()).decode('utf-8')
        plt.close()

        return image_base64

    def get_packet_dataframe(self):
        """Return packet data as pandas DataFrame"""
        return pd.DataFrame(self.packets)
