import threading
import time
from packet_sniffer import start_sniffing
from anomaly_detector import detect_anomalies
from deep_packet_inspection import start_inspection
from traffic_simulator import send_traffic
from log_handler import log_event

def run_sniffer():
    """ Start packet sniffing in a separate thread. """
    log_event("[+] Starting packet sniffer...")
    start_sniffing(interface="Wi-Fi", count=50)

def run_inspector():
    """ Start deep packet inspection in a separate thread. """
    log_event("[+] Starting deep packet inspection...")
    start_inspection(interface="Wi-Fi", count=50)

if __name__ == "__main__":
    print("[+] Running network analysis module...")
    log_event("[+] Network analysis module started.")

    # Step 1: Start sniffer and DPI in separate threads
    sniffer_thread = threading.Thread(target=run_sniffer)
    dpi_thread = threading.Thread(target=run_inspector)

    sniffer_thread.start()
    dpi_thread.start()

    # Step 2: Simulate traffic
    time.sleep(2)  # Give the sniffer some time to start
    send_traffic(interface="Wi-Fi", num_packets=50, malicious_chance=0.2)

    # Step 3: Wait for sniffer and DPI to finish
    sniffer_thread.join()
    dpi_thread.join()

    # Step 4: Detect anomalies
    log_event("[+] Running anomaly detection...")
    detect_anomalies()

    print("[+] Network analysis complete!")
    log_event("[+] Network analysis finished.")
