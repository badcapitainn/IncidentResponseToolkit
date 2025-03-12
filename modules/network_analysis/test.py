from capture import start_capture
from simulator import simulate_legitimate_traffic, simulate_attack
from logger import log_info

if __name__ == "__main__":
    log_info("Starting Network Analysis Module...")

    # Simulate normal and attack traffic
    simulate_legitimate_traffic()
    simulate_attack()

    # Start capturing network traffic
    start_capture()
