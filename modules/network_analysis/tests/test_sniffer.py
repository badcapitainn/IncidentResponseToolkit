import unittest
from packet_sniffer import start_sniffing

class TestPacketSniffer(unittest.TestCase):
    def test_sniffing(self):
        """ Ensure the packet sniffer runs without errors. """
        try:
            start_sniffing(interface="lo", count=10)  # Use loopback interface for testing
            self.assertTrue(True)
        except Exception:
            self.assertTrue(False)

if __name__ == "__main__":
    unittest.main()
