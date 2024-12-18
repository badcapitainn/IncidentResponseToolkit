import json
from datetime import datetime, timedelta
import random


def generate_dummy_logs(file_path: str, num_logs: int = 500) -> None:
    """
    Generate a dummy JSON log file with random events.
    :param file_path: Path to save the log file.
    :param num_logs: Number of log entries to generate.
    """
    events = []
    event_types = ["failed_login", "http_request"]
    for _ in range(num_logs):
        event = {
            "timestamp": (datetime.now() - timedelta(seconds=random.randint(0, 3600))).strftime("%Y-%m-%dT%H:%M:%S"),
            "ip_address": f"192.168.1.{random.randint(1, 255)}",
            "event_type": random.choice(event_types),
        }
        events.append(event)

    with open(file_path, "w") as file:
        json.dump(events, file, indent=4)


# Generate a test log file

generate_dummy_logs("C:\\Users\\madza\\PycharmProjects\\IncidentResponseToolkit\\logs\\test_logs.json")
