from loguru import logger
import os
import json
from datetime import datetime
from collections import defaultdict

# Set up log file directory
LOG_DIR: str = "logs/"
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

# Configure Loguru logger
logger.add(
    f"{LOG_DIR}/log_analysis_{datetime.now().strftime('%Y%m%d')}.log",
    rotation="10 MB",  # Create a new log file if the size exceeds 10 MB
    compression="zip",  # Compress old log files
    retention="7 days",  # Retain logs for 7 days
    level="INFO"  # Log level
)


def log_event(level: str, message: any) -> None:
    """
    Log an event with a specific level and message.
    :param level: Log level (e.g., 'info', 'warning', 'error')
    :param message: Log message
    """
    if level.lower() == "info":
        logger.info(message)
    elif level.lower() == "warning":
        logger.warning(message)
    elif level.lower() == "error":
        logger.error(message)
    else:
        logger.debug(message)


def filter_logs(log_file: any, level: str = "ERROR") -> list:
    """
    Filter logs based on their severity level.
    :param log_file: Path to the log file to analyze
    :param level: Minimum log level to filter (e.g., 'ERROR')
    :return: Filtered log entries as a list
    """
    filtered_logs: list = []
    with open(log_file, "r") as file:
        for line in file:
            if level in line:
                filtered_logs.append(line)
    return filtered_logs


def compress_logs() -> None:
    """
    Compress logs that exceed a certain retention period.
    """
    logger.info("Compressing old logs...")
    # Loguru built-in compression handles this automatically.


def parse_logs(log_file) -> list:
    """
    Parse log entries from a log file.
    :param log_file: Path to the log file.
    :return: List of log lines.
    """
    with open(log_file, "r") as file:
        logs: list = json.load(file)
    return logs


def detect_brute_force(logs: list, max_attempts: int = 5, time_window: int = 60) -> list:
    """
    Detect brute force attacks from log entries.
    :param logs: List of log entries.
    :param max_attempts: Max allowed failed attempts before flagging.
    :param time_window: Time window (seconds) for attempts.
    :return: List of brute force attack alerts.
    """
    failed_attempts: defaultdict = defaultdict(list)
    alerts: list = []

    for log in logs:
        if log.get("event_type") == "failed_login":
            ip_address: any = log.get("ip_address")
            timestamp: datetime = datetime.strptime(log.get("timestamp"), "%Y-%m-%dT%H:%M:%S")

            # Record the failed attempt
            failed_attempts[ip_address].append(timestamp)

            # Filter out old attempts outside the time window
            failed_attempts[ip_address] = [
                t for t in failed_attempts[ip_address]
                if (timestamp - t).seconds <= time_window
            ]

            # Trigger an alert if max attempts are exceeded
            if len(failed_attempts[ip_address]) > max_attempts:
                alert_message: str = f"Brute force detected from {ip_address} ({len(failed_attempts[ip_address])} attempts)"
                alerts.append(alert_message)
                logger.warning(alert_message)
    return alerts


# Detect DDoS attacks
def detect_ddos(logs: list, max_requests: int = 100, time_window: int = 10) -> list:
    """
    Detect potential DDoS attacks from log entries.
    :param logs: List of log entries.
    :param max_requests: Max allowed requests from an IP within time window.
    :param time_window: Time window (seconds) for requests.
    :return: List of DDoS attack alerts.
    """
    request_counts: defaultdict = defaultdict(list)
    alerts: list = []

    for log in logs:
        if log.get("event_type") == "http_request":
            ip_address = log.get("ip_address")
            timestamp = datetime.strptime(log.get("timestamp"), "%Y-%m-%dT%H:%M:%S")

            # Record the request
            request_counts[ip_address].append(timestamp)

            # Filter out old requests outside the time window
            request_counts[ip_address] = [
                t for t in request_counts[ip_address]
                if (timestamp - t).seconds <= time_window
            ]

            # Trigger an alert if max requests are exceeded
            if len(request_counts[ip_address]) > max_requests:
                alert_message: str = f"DDoS detected from {ip_address} ({len(request_counts[ip_address])} requests in {time_window}s)"
                alerts.append(alert_message)
                logger.warning(alert_message)

    return alerts


# Run log analysis

def analyze_logs(log_file) -> list:
    """
    Analyze logs for brute force and DDoS attacks.
    :param log_file: Path to the log file.
    :return: Combined list of alerts.
    """
    logs = parse_logs(log_file)
    brute_force_alerts: list = detect_brute_force(logs)
    ddos_alerts: list = detect_ddos(logs)
    return brute_force_alerts + ddos_alerts
