from collections import defaultdict
import dpkt
import socket
import datetime
from scapy.layers.inet import IP, TCP, UDP
import pandas as pd


class NetworkAnalyzer:
    def __init__(self, capture_file):
        self.capture_file = capture_file
        self.packets = []
        self.stats = {
            'total_packets': 0,
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
                            packet['flags'] = self._get_tcp_flags(ip.data)
                        elif isinstance(ip.data, dpkt.udp.UDP):
                            packet['src_port'] = ip.data.sport
                            packet['dst_port'] = ip.data.dport
                            packet['protocol_name'] = 'UDP'
                        else:
                            packet['protocol_name'] = 'Other'

                        self.packets.append(packet)
                        self.update_stats(packet)

                    except Exception as e:
                        continue
        except Exception as e:
            print(f"Error loading PCAP: {e}")

    def _get_tcp_flags(self, tcp):
        """Extract TCP flags from packet"""
        flags = []
        if tcp.flags & dpkt.tcp.TH_FIN:
            flags.append('FIN')
        if tcp.flags & dpkt.tcp.TH_SYN:
            flags.append('SYN')
        if tcp.flags & dpkt.tcp.TH_RST:
            flags.append('RST')
        if tcp.flags & dpkt.tcp.TH_PUSH:
            flags.append('PSH')
        if tcp.flags & dpkt.tcp.TH_ACK:
            flags.append('ACK')
        if tcp.flags & dpkt.tcp.TH_URG:
            flags.append('URG')
        return ' '.join(flags) if flags else 'None'

    def update_stats(self, packet):
        """Update statistics with packet data"""
        self.stats['total_packets'] += 1

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
        """Return protocol distribution data as dict"""
        return dict(self.stats['protocols'])

    def get_top_ips(self, count=10, type='source'):
        """Return top source or destination IPs"""
        ips = self.stats['source_ips'] if type == 'source' else self.stats['dest_ips']
        return dict(sorted(ips.items(), key=lambda x: x[1], reverse=True)[:count])

    def get_top_ports(self, count=10):
        """Return top ports"""
        return dict(sorted(self.stats['ports'].items(), key=lambda x: x[1], reverse=True)[:count])

    def get_timeline_data(self):
        """Return sorted timeline data"""
        timeline = sorted(self.stats['timeline'].items())
        if not timeline:
            return {}, {}
        return dict(timeline)

    def get_packet_dataframe(self):
        """Return packet data as pandas DataFrame"""
        return pd.DataFrame(self.packets)

    def get_analysis_summary(self):
        """Return all analysis data in a structured format"""
        return {
            'total_packets': self.stats['total_packets'],
            'protocol_distribution': self.get_protocol_distribution(),
            'top_source_ips': self.get_top_ips(type='source'),
            'top_dest_ips': self.get_top_ips(type='dest'),
            'top_ports': self.get_top_ports(),
            'timeline': self.get_timeline_data(),
            'start_time': self.stats['start_time'],
            'end_time': self.stats['end_time']
        }