import json


def detect_anomalies(log_file="network_logs.json"):
    """ Detects potential anomalies in captured network traffic. """
    src_counts = {}
    threshold = 50  # Example: flag if a single IP sends over 50 packets

    with open(log_file, "r") as file:
        for line in file:
            packet = json.loads(line)
            src_ip = packet.get("src", "Unknown")
            src_counts[src_ip] = src_counts.get(src_ip, 0) + 1

    anomalies = {ip: count for ip, count in src_counts.items() if count > threshold}

    if anomalies:
        print("Anomalies Detected:", anomalies)
    else:
        print("No anomalies detected.")


if __name__ == "__main__":
    detect_anomalies()
