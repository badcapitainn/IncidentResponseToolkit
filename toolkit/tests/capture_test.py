import os
import threading
from unittest import TestCase, mock
from datetime import datetime
from collections import defaultdict
from django.conf import settings
import pydivert
from scapy.all import IP, TCP, UDP, Raw
import dpkt

from modules.network.capture import NetworkCapture  # Replace with your actual module path


class TestNetworkCapture(TestCase):
    def setUp(self):
        self.capture = NetworkCapture()
        self.sample_packet = {
            'src_ip': '192.168.1.1',
            'dst_ip': '10.0.0.1',
            'src_port': 54321,
            'dst_port': 80,
            'protocol': 'TCP',
            'timestamp': datetime.now().timestamp(),
            'raw': b'mock_packet_data'
        }
        
        # Mock the packet_to_dict function
        self.patcher = mock.patch('your_module.packet_to_dict')
        self.mock_packet_to_dict = self.patcher.start()
        self.mock_packet_to_dict.return_value = self.sample_packet

    def tearDown(self):
        self.patcher.stop()
        if os.path.exists(self.capture.capture_file):
            os.remove(self.capture.capture_file)

    @mock.patch('pydivert.WinDivert')
    def test_start_capture_success(self, mock_windivert):
        # Test successful capture start
        result = self.capture.start_capture()
        self.assertTrue(result)
        self.assertTrue(self.capture.capture_active)
        self.assertIsInstance(self.capture.capture_thread, threading.Thread)
        
        # Clean up
        self.capture.stop_capture()

    def test_start_capture_when_active(self):
        # Test starting when already active
        self.capture.capture_active = True
        result = self.capture.start_capture()
        self.assertFalse(result)

    @mock.patch('pydivert.WinDivert')
    def test_stop_capture(self, mock_windivert):
        self.capture.start_capture()
        self.capture.stop_capture()
        self.assertFalse(self.capture.capture_active)

    @mock.patch('pydivert.WinDivert')
    @mock.patch.object(NetworkCapture, 'process_packet')
    def test_capture_loop(self, mock_process, mock_windivert):
        # Mock the WinDivert context manager
        mock_divert = mock.MagicMock()
        mock_divert.recv.side_effect = [
            mock.MagicMock(raw=b'packet1'),
            mock.MagicMock(raw=b'packet2'),
            KeyboardInterrupt()  # To break the loop
        ]
        mock_windivert.return_value.__enter__.return_value = mock_divert
        
        self.capture.start_capture()
        time.sleep(0.1)  # Give thread time to start
        self.capture.capture_active = False  # Simulate stop
        self.capture.capture_thread.join()
        
        self.assertEqual(mock_process.call_count, 2)

    @mock.patch('scapy.all.IP')
    def test_process_packet_success(self, mock_ip):
        # Setup mock scapy packet
        mock_pkt = mock.MagicMock()
        mock_ip.return_value = mock_pkt
        mock_pkt.haslayer.return_value = False
        
        raw_packet = mock.MagicMock()
        raw_packet.raw = b'mock_packet_data'
        
        self.capture.process_packet(raw_packet)
        
        self.assertEqual(len(self.capture.packets), 1)
        self.assertEqual(self.capture.stats['total_packets'], 1)

    @mock.patch('scapy.all.IP', side_effect=Exception("Parse error"))
    def test_process_packet_error(self, mock_ip):
        with mock.patch('builtins.print') as mock_print:
            self.capture.process_packet(mock.MagicMock())
            mock_print.assert_called_once_with("Packet processing error: Parse error")

    def test_update_stats(self):
        self.capture.update_stats(self.sample_packet)
        
        stats = self.capture.stats
        self.assertEqual(stats['total_packets'], 1)
        self.assertEqual(stats['protocols']['TCP'], 1)
        self.assertEqual(stats['source_ips']['192.168.1.1'], 1)
        self.assertEqual(stats['dest_ips']['10.0.0.1'], 1)
        self.assertEqual(stats['ports'][54321], 1)
        self.assertEqual(stats['ports'][80], 1)

    def test_check_rules(self):
        # Create a mock rule
        mock_rule = mock.MagicMock()
        mock_rule.matches.return_value = True
        mock_rule.id = 1
        mock_rule.name = "Test Rule"
        mock_rule.severity = "High"
        
        self.capture.rules = [mock_rule]
        self.capture.check_rules(self.sample_packet)
        
        self.assertEqual(len(self.capture.alerts), 1)
        alert = self.capture.alerts[0]
        self.assertEqual(alert['rule_id'], 1)
        self.assertEqual(alert['rule_name'], "Test Rule")
        self.assertEqual(alert['severity'], "High")

    @mock.patch('dpkt.pcap.Writer')
    def test_save_to_pcap(self, mock_writer):
        # Add some test packets
        self.capture.packets = [
            {'raw': b'packet1', 'timestamp': 1234567890},
            {'raw': b'packet2', 'timestamp': 1234567891}
        ]
        
        self.capture.save_to_pcap()
        
        # Verify the writer was called with our packets
        mock_writer.return_value.writepkt.assert_any_call(b'packet1', 1234567890)
        mock_writer.return_value.writepkt.assert_any_call(b'packet2', 1234567891)

    @mock.patch('dpkt.pcap.Writer', side_effect=Exception("Write error"))
    def test_save_to_pcap_error(self, mock_writer):
        with mock.patch('builtins.print') as mock_print:
            self.capture.save_to_pcap()
            mock_print.assert_called_once_with("Error saving PCAP: Write error")

    def test_clear_capture(self):
        # Add some data
        self.capture.packets = [self.sample_packet]
        self.capture.alerts = [{'test': 'alert'}]
        self.capture.stats['total_packets'] = 1
        
        self.capture.clear_capture()
        
        self.assertEqual(len(self.capture.packets), 0)
        self.assertEqual(len(self.capture.alerts), 0)
        self.assertEqual(self.capture.stats['total_packets'], 0)


class TestNetworkCaptureIntegration(TestCase):
    def setUp(self):
        self.capture = NetworkCapture()
        self.test_pcap = os.path.join(settings.BASE_DIR, 'test_capture.pcap')

    def tearDown(self):
        if os.path.exists(self.capture.capture_file):
            os.remove(self.capture.capture_file)

    def test_save_and_load_pcap_integration(self):
        # Create test packets
        test_packets = [
            {'raw': b'test_packet_1', 'timestamp': 1234567890},
            {'raw': b'test_packet_2', 'timestamp': 1234567891}
        ]
        self.capture.packets = test_packets
        
        # Save to file
        self.capture.save_to_pcap()
        
        # Verify file was created
        self.assertTrue(os.path.exists(self.capture.capture_file))
        
        # Verify file content (basic check)
        with open(self.capture.capture_file, 'rb') as f:
            content = f.read()
            self.assertIn(b'test_packet_1', content)
            self.assertIn(b'test_packet_2', content)