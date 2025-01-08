import os
import re
import time
import threading
from datetime import datetime, timedelta
from collections import defaultdict
from loguru import logger
import psutil

# Regular expression to parse Apache logs
LOG_PATTERN = re.compile(
    r'(?P<ip>[\d\.]+) - - \[(?P<timestamp>[^\]]+)\] "(?P<method>[A-Z]+) (?P<url>[^\s]+) (?P<protocol>[^\"]+)" (?P<status>\d{3}) (?P<bytes>\d+) "(?P<user_agent>[^"]+)"'
)

# Configurations
LOG_DIR = "../logs"
LOG_FILE = f"{LOG_DIR}/apache_logs.log"
THRESHOLDS = {
    "brute_force": {"attempts": 5, "time_window": 300},  # 5 attempts in 5 minutes
    "ddos": {"requests": 50, "time_window": 10},  # 50 requests in 10 seconds
    "resource_monitoring_interval": 5,  # Check every 5 seconds
}

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


# Helper functions
def parse_log_entry(log_entry):
    match = LOG_PATTERN.match(log_entry)
    if match:
        return match.groupdict()
    return None


def parse_timestamp(timestamp):
    try:
        return datetime.strptime(timestamp, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return datetime.strptime(timestamp.strip(), "%d/%b/%Y:%H:%M:%S")


# Detection functions
def detect_brute_force(logs):
    failed_logins = defaultdict(list)
    alerts = []
    current_time = datetime.now()

    for log in logs:
        if log['url'] == '/login' and log['status'] == '401':  # Unauthorized
            ip = log['ip']
            timestamp = parse_timestamp(log['timestamp'])
            failed_logins[ip].append(timestamp)

    for ip, timestamps in failed_logins.items():
        recent_attempts = [t for t in timestamps if
                           (current_time - t).seconds <= THRESHOLDS['brute_force']['time_window']]
        if len(recent_attempts) >= THRESHOLDS['brute_force']['attempts']:
            alerts.append(f"Brute-force attack detected from IP: {ip}")
            logger.warning(
                f"{ip} failed login attempts detected within {THRESHOLDS['brute_force']['time_window']} seconds")

    return alerts


def detect_ddos(logs):
    ip_requests = defaultdict(list)
    alerts = []
    current_time = datetime.now()

    for log in logs:
        ip = log['ip']
        timestamp = parse_timestamp(log['timestamp'])
        ip_requests[ip].append(timestamp)

    for ip, timestamps in ip_requests.items():
        recent_requests = [t for t in timestamps if (current_time - t).seconds <= THRESHOLDS['ddos']['time_window']]
        if len(recent_requests) >= THRESHOLDS['ddos']['requests']:
            alerts.append(f"DDoS attack detected from IP: {ip}")
            logger.warning(
                f"DDoS attack: {ip} made {len(recent_requests)} requests in {THRESHOLDS['ddos']['time_window']} seconds")

    return alerts


def detect_sql_injection(logs):
    sql_patterns = [r"(?i)(UNION|SELECT|DROP|INSERT|DELETE|--|;|%27|%22|%3D)"]
    alerts = []

    for log in logs:
        if any(re.search(pattern, log['url']) for pattern in sql_patterns):
            alerts.append(f"SQL Injection attempt detected in URL: {log['url']}")
            logger.warning(f"SQL Injection detected: {log['url']}")

    return alerts


def detect_xss(logs):
    xss_patterns = [r"(?i)(<script>|<img|javascript:|onerror=)"]
    alerts = []

    for log in logs:
        if any(re.search(pattern, log['url']) for pattern in xss_patterns):
            alerts.append(f"XSS attack attempt detected in URL: {log['url']}")
            logger.warning(f"XSS attack detected: {log['url']}")

    return alerts


# Real-time log analyzer
def analyze_logs_in_real_time():
    with open(LOG_FILE, "r") as file:
        file.seek(0, os.SEEK_END)
        while True:
            line = file.readline()
            if line:
                log_entry = parse_log_entry(line)
                if log_entry:
                    logs = [log_entry]
                    alerts = (
                            detect_brute_force(logs) +
                            detect_ddos(logs) +
                            detect_sql_injection(logs) +
                            detect_xss(logs)
                    )
                    for alert in alerts:
                        logger.error(alert)
            time.sleep(0.1)


def generate_logs():
    """Simulates log generation by writing random logs, including attack patterns, to a file."""
    from faker import Faker
    import random

    fake = Faker()

    http_methods = ["GET", "POST", "PUT", "DELETE"]
    status_codes = [200, 401, 403, 404, 500]
    normal_urls = ["/home", "/about", "/contact", "/products", "/login", "/register"]
    sql_injection_patterns = ["' OR '1'='1", "'; DROP TABLE users; --", "' UNION SELECT * FROM users; --"]
    xss_patterns = ["<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>", "javascript:alert('XSS')"]
    brute_force_ips = [fake.ipv4() for _ in range(3)]  # Fixed IPs for simulating brute-force attempts

    while True:
        # Randomly decide whether to generate a normal log or simulate an attack
        log_type = random.choices(
            ["normal", "brute_force", "ddos", "sql_injection", "xss"],
            weights=[60, 10, 10, 10, 10],  # Adjust weights to control frequency of each type
            k=1
        )[0]

        ip = fake.ipv4()
        method = random.choice(http_methods)
        status = random.choice(status_codes)
        url = random.choice(normal_urls)
        response_size = random.randint(100, 10000)

        if log_type == "brute_force":
            # Simulate repeated failed login attempts from the same IP
            ip = random.choice(brute_force_ips)
            url = "/login"
            status = 401  # Unauthorized

        elif log_type == "ddos":
            # Simulate high request rates from the same IP
            ip = fake.ipv4()

        elif log_type == "sql_injection":
            # Simulate SQL injection attempts
            url = random.choice(sql_injection_patterns)

        elif log_type == "xss":
            # Simulate XSS attempts
            url = random.choice(xss_patterns)

        # Format the log entry
        log_entry = (
            f"{ip} - - "
            f"[{datetime.now().strftime('%d/%b/%Y:%H:%M:%S %z')}] "
            f"\"{method} {url} HTTP/1.1\" "
            f"{status} {response_size}"
        )

        # Write the log entry to the file
        with open(LOG_FILE, "a") as file:
            file.write(log_entry + "\n")

        # Add some randomness to log generation speed
        time.sleep(random.uniform(0.1, 1.0))


# Resource monitoring
def monitor_resources():
    while True:
        cpu_usage = psutil.cpu_percent(interval=THRESHOLDS['resource_monitoring_interval'])
        memory_info = psutil.virtual_memory()
        memory_usage = memory_info.percent
        disk_usage = psutil.disk_usage('/').percent

        logger.info(f"Resource Usage: CPU={cpu_usage}%, Memory={memory_usage}%, Disk={disk_usage}%")
        time.sleep(THRESHOLDS['resource_monitoring_interval'])


# Main entry point
if __name__ == "__main__":
    try:
        generate_thread = threading.Thread(target=generate_logs)
        log_thread = threading.Thread(target=analyze_logs_in_real_time, daemon=True)
        resource_monitor_thread = threading.Thread(target=monitor_resources, daemon=True)

        generate_thread.start()
        log_thread.start()
        resource_monitor_thread.start()

        generate_thread.join()
        log_thread.join()
        resource_monitor_thread.join()
    except KeyboardInterrupt:
        print("\nExiting...")
