import unittest
from deep_packet_inspection import start_inspection

class TestDPI(unittest.TestCase):
    def test_dpi(self):
        """ Ensure DPI runs without crashing. """
        try:
            start_inspection(interface="lo", count=10)  # Loopback for testing
            self.assertTrue(True)
        except Exception:
            self.assertTrue(False)

if __name__ == "__main__":
    unittest.main()
