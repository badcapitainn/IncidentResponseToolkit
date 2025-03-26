import unittest
from modules.network_analysis.anomaly_detector import detect_anomalies


class TestAnomalyDetection(unittest.TestCase):
    def test_anomaly_detection(self):
        """ Check if anomaly detection runs successfully. """
        try:
            detect_anomalies()
            self.assertTrue(True)
        except Exception:
            self.assertTrue(False)


if __name__ == "__main__":
    unittest.main()
