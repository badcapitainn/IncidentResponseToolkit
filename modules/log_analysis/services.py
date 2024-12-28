import re
import os
from collections import defaultdict
from datetime import datetime, timedelta
from loguru import logger


# Regular expression to parse Apache logs
LOG_PATTERN = re.compile(
    r'(?P<ip>[\d\.]+) - - \[(?P<timestamp>[^\]]+)\] "(?P<method>[A-Z]+) (?P<url>[^\s]+) (?P<protocol>[^\"]+)" (?P<status>\d{3}) (?P<bytes>\d+)'
)

LOG_DIR = "logs/"
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

# Configure Loguru logger
logger.add(
    f"{LOG_DIR}/log_analysis_{datetime.now().strftime('%Y%m%d')}.log",
    rotation="10 MB",
    compression="zip",
    retention="7 days",
    level="INFO"
)


def parse_log_entry(log_entry):
    """Parses a single Apache log entry."""
    match = LOG_PATTERN.match(log_entry)
    if match:
        return match.groupdict()
    return None


def parse_timestamp(timestamp):
    """Converts Apache timestamp to datetime object."""
    return datetime.strptime(timestamp, "%d/%b/%Y:%H:%M:%S %z")


def detect_brute_force(logs, threshold=5):
    """Detects brute-force attempts based on repeated failed login attempts."""
    failed_logins = defaultdict(list)

    for log in logs:
        if log['url'] == '/login' and log['status'] == '401':  # Unauthorized
            ip = log['ip']
            timestamp = parse_timestamp(log['timestamp'])
            failed_logins[ip].append(timestamp)

    # Identify IPs exceeding the threshold
    brute_force_ips = []
    for ip, timestamps in failed_logins.items():
        if len(timestamps) >= threshold:
            brute_force_ips.append(ip)
            logger.warning(f"{ip} failed login attempts")

    return brute_force_ips


def detect_ddos(logs, time_window=1, request_threshold=50):
    """
    Detects potential DDoS attacks based on high request rates from multiple IPs.
    """
    request_counts = defaultdict(int)
    ddos_ips = []

    for log in logs:
        ip = log['ip']
        timestamp = parse_timestamp(log['timestamp'])
        request_counts[(ip, timestamp)] += 1

    # Aggregate counts per IP
    ip_request_totals = defaultdict(int)
    for (ip, timestamp), count in request_counts.items():
        ip_request_totals[ip] += count

    # Identify IPs exceeding the request threshold
    for ip, total in ip_request_totals.items():
        if total >= request_threshold:
            ddos_ips.append(ip)
            logger.warning(f"{ip}: {total}")

    return ddos_ips


def analyze_logs(file_path):
    """Processes the log file and identifies anomalies."""
    with open(file_path, 'r') as file:
        logs = []
        for line in file:
            parsed_entry = parse_log_entry(line)
            if parsed_entry:
                logs.append(parsed_entry)

    # Detect anomalies
    brute_force_ips = detect_brute_force(logs)
    ddos_ips = detect_ddos(logs)

    # Generate Alerts
    alerts = []
    if brute_force_ips:
        alerts.append(f"Brute-force attack detected from IPs: {', '.join(brute_force_ips)}")
    if ddos_ips:
        alerts.append(f"DDoS attack detected from IPs: {', '.join(ddos_ips)}")

    return alerts
