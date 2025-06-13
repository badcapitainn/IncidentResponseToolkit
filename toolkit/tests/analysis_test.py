import os
import socket
import datetime
from unittest import TestCase, mock
from collections import defaultdict
import dpkt
import pandas as pd
from scapy.layers.inet import IP, TCP, UDP

from modules.network.analysis import NetworkAnalyzer  # Replace with your actual module path


class TestNetworkAnalyzer(TestCase):
    def setUp(self):
        # Create a test PCAP file path
        self.test_pcap = "test_capture.pcap"
        self.analyzer = NetworkAnalyzer(self.test_pcap)
        
        # Sample packet data for testing
        self.sample_packet_tcp = {
            'timestamp': 1630000000.0,
            'src_ip': '192.168.1.1',
            'dst_ip': '10.0.0.1',
            'protocol': 6,  # TCP
            'size': 1500,
            'src_port': 54321,
            'dst_port': 80,
            'protocol_name': 'TCP',
            'flags': 'SYN ACK'
        }
        
        self.sample_packet_udp = {
            'timestamp': 1630000001.0,
            'src_ip': '10.0.0.2',
            'dst_ip': '192.168.1.2',
            'protocol': 17,  # UDP
            'size': 512,
            'src_port': 12345,
            'dst_port': 53,
            'protocol_name': 'UDP'
        }

    @mock.patch('builtins.open')
    @mock.patch('dpkt.pcap.Reader')
    def test_load_pcap_success(self, mock_reader, mock_open):
        # Setup mock pcap reader
        mock_pcap = mock.MagicMock()
        mock_pcap.__iter__.return_value = [
            (1630000000.0, b'mock_packet_data'),
            (1630000001.0, b'mock_packet_data')
        ]
        mock_reader.return_value = mock_pcap
        
        # Setup mock ethernet packet
        mock_eth = mock.MagicMock()
        mock_ip = mock.MagicMock()
        mock_ip.src = socket.inet_aton('192.168.1.1')
        mock_ip.dst = socket.inet_aton('10.0.0.1')
        mock_ip.p = 6  # TCP
        mock_ip.data = mock.MagicMock(spec=dpkt.tcp.TCP)
        mock_ip.data.sport = 54321
        mock_ip.data.dport = 80
        mock_eth.data = mock_ip
        dpkt.ethernet.Ethernet = mock.MagicMock(return_value=mock_eth)
        
        # Call the method
        self.analyzer.load_pcap()
        
        # Verify results
        self.assertEqual(len(self.analyzer.packets), 2)
        self.assertEqual(self.analyzer.stats['total_packets'], 2)
        self.assertEqual(self.analyzer.stats['protocols']['TCP'], 2)

    @mock.patch('builtins.open')
    @mock.patch('dpkt.pcap.Reader')
    def test_load_pcap_error(self, mock_reader, mock_open):
        mock_reader.side_effect = Exception("PCAP read error")
        
        with mock.patch('builtins.print') as mock_print:
            self.analyzer.load_pcap()
            mock_print.assert_called_once_with("Error loading PCAP: PCAP read error")

    def test_get_tcp_flags(self):
        # Create a mock TCP packet with SYN and ACK flags
        mock_tcp = mock.MagicMock()
        mock_tcp.flags = dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK
        
        flags = self.analyzer._get_tcp_flags(mock_tcp)
        self.assertEqual(flags, "SYN ACK")

    def test_update_stats(self):
        # Test with TCP packet
        self.analyzer.update_stats(self.sample_packet_tcp)
        
        self.assertEqual(self.analyzer.stats['total_packets'], 1)
        self.assertEqual(self.analyzer.stats['protocols']['TCP'], 1)
        self.assertEqual(self.analyzer.stats['source_ips']['192.168.1.1'], 1)
        self.assertEqual(self.analyzer.stats['dest_ips']['10.0.0.1'], 1)
        self.assertEqual(self.analyzer.stats['ports'][54321], 1)
        self.assertEqual(self.analyzer.stats['ports'][80], 1)
        
        # Test timeline formatting
        expected_minute = datetime.datetime.fromtimestamp(1630000000.0).strftime('%Y-%m-%d %H:%M')
        self.assertEqual(self.analyzer.stats['timeline'][expected_minute], 1)
        
        # Test start/end time
        self.assertEqual(self.analyzer.stats['start_time'], 1630000000.0)
        self.assertEqual(self.analyzer.stats['end_time'], 1630000000.0)
        
        # Test with UDP packet
        self.analyzer.update_stats(self.sample_packet_udp)
        self.assertEqual(self.analyzer.stats['total_packets'], 2)
        self.assertEqual(self.analyzer.stats['protocols']['UDP'], 1)

    def test_get_protocol_distribution(self):
        # Add test data
        self.analyzer.stats['protocols']['TCP'] = 5
        self.analyzer.stats['protocols']['UDP'] = 3
        
        result = self.analyzer.get_protocol_distribution()
        self.assertEqual(result, {'TCP': 5, 'UDP': 3})

    def test_get_top_ips(self):
        # Add test data
        self.analyzer.stats['source_ips'] = defaultdict(int, {
            '192.168.1.1': 10,
            '10.0.0.1': 5,
            '172.16.0.1': 3
        })
        
        # Test source IPs
        result = self.analyzer.get_top_ips(count=2, type='source')
        self.assertEqual(result, {'192.168.1.1': 10, '10.0.0.1': 5})
        
        # Test dest IPs
        self.analyzer.stats['dest_ips'] = defaultdict(int, {
            '8.8.8.8': 15,
            '1.1.1.1': 8
        })
        result = self.analyzer.get_top_ips(count=1, type='dest')
        self.assertEqual(result, {'8.8.8.8': 15})

    def test_get_top_ports(self):
        # Add test data
        self.analyzer.stats['ports'] = defaultdict(int, {
            80: 50,
            443: 30,
            22: 10
        })
        
        result = self.analyzer.get_top_ports(count=2)
        self.assertEqual(result, {80: 50, 443: 30})

    def test_get_timeline_data(self):
        # Add test data
        self.analyzer.stats['timeline'] = defaultdict(int, {
            '2021-08-27 12:00': 10,
            '2021-08-27 12:01': 5,
            '2021-08-27 11:59': 3
        })
        
        result = self.analyzer.get_timeline_data()
        self.assertEqual(list(result.keys())[0], '2021-08-27 11:59')
        self.assertEqual(list(result.keys())[-1], '2021-08-27 12:01')

    @mock.patch('pandas.DataFrame')
    def test_get_packet_dataframe(self, mock_df):
        self.analyzer.packets = [self.sample_packet_tcp, self.sample_packet_udp]
        result = self.analyzer.get_packet_dataframe()
        mock_df.assert_called_once_with([self.sample_packet_tcp, self.sample_packet_udp])

    def test_get_analysis_summary(self):
        # Add test data
        self.analyzer.stats = {
            'total_packets': 100,
            'protocols': defaultdict(int, {'TCP': 70, 'UDP': 30}),
            'source_ips': defaultdict(int, {'192.168.1.1': 50}),
            'dest_ips': defaultdict(int, {'8.8.8.8': 40}),
            'ports': defaultdict(int, {80: 60}),
            'timeline': defaultdict(int, {'2021-08-27 12:00': 10}),
            'start_time': 1630000000.0,
            'end_time': 1630000100.0
        }
        
        result = self.analyzer.get_analysis_summary()
        self.assertEqual(result['total_packets'], 100)
        self.assertEqual(result['protocol_distribution'], {'TCP': 70, 'UDP': 30})
        self.assertEqual(result['top_source_ips'], {'192.168.1.1': 50})
        self.assertEqual(result['top_dest_ips'], {'8.8.8.8': 40})
        self.assertEqual(result['top_ports'], {80: 60})
        self.assertEqual(result['start_time'], 1630000000.0)


class TestNetworkAnalyzerIntegration(TestCase):
    def setUp(self):
        # Create a small test PCAP file
        self.test_pcap = "test_integration.pcap"
        self.create_test_pcap()
        self.analyzer = NetworkAnalyzer(self.test_pcap)

    def tearDown(self):
        if os.path.exists(self.test_pcap):
            os.remove(self.test_pcap)

    def create_test_pcap(self):
        """Create a simple test PCAP file with minimal data"""
        from scapy.all import wrpcap, Ether, IP, TCP, UDP
        
        # Create a few test packets
        packets = [
            Ether()/IP(src="192.168.1.1", dst="8.8.8.8")/TCP(sport=54321, dport=80),
            Ether()/IP(src="10.0.0.1", dst="192.168.1.2")/UDP(sport=12345, dport=53)
        ]
        
        # Write to file
        wrpcap(self.test_pcap, packets)

    def test_load_pcap_integration(self):
        self.analyzer.load_pcap()
        
        # Basic verification
        self.assertEqual(self.analyzer.stats['total_packets'], 2)
        self.assertEqual(self.analyzer.stats['protocols']['TCP'], 1)
        self.assertEqual(self.analyzer.stats['protocols']['UDP'], 1)
        
        # Verify IPs
        self.assertEqual(self.analyzer.stats['source_ips']['192.168.1.1'], 1)
        self.assertEqual(self.analyzer.stats['source_ips']['10.0.0.1'], 1)
        
        # Verify ports
        self.assertEqual(self.analyzer.stats['ports'][80], 1)
        self.assertEqual(self.analyzer.stats['ports'][53], 1)