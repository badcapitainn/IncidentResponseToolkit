import os
import re
import time
from datetime import datetime, timedelta
from collections import defaultdict
from loguru import logger
import psutil


class LogAnalysis:
    LOG_PATTERN = re.compile(
        r'(?P<ip>[\d.]+) - - \[(?P<timestamp>[^\]]+)\s*\] "(?P<method>[A-Z]+) (?P<url>[^"]+) (?P<protocol>[^"]+)" (?P<status>\d{3}) (?P<bytes>\d+)( "(?P<user_agent>[^"]+)")?'
    )

    # Configurations
    THRESHOLDS = {
        "brute_force": {"attempts": 5, "time_window": 300},  # 5 attempts in 5 minutes
        "ddos": {"requests": 5, "time_window": 5},  # 50 requests in 10 seconds
        "resource_monitoring_interval": 5,  # Check every 5 seconds
    }

    def __init__(self, log_dir, log_file):
        self.log_dir = log_dir
        self.log_file = log_file
        self.processed_logs = set()
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
        logger.add(
            f"{self.log_dir}/log_analysis_{datetime.now().strftime('%Y%m%d')}.log",
            rotation="10 MB",
            compression="zip",
            retention="7 days",
            level="INFO"
        )

    def parse_log_entry(self, log_entry):
        match = self.LOG_PATTERN.match(log_entry)
        if match:
            return match.groupdict()
        logger.debug(f"Failed to parse log entry: {log_entry}")
        return None

    def parse_timestamp(self, timestamp):
        try:
            # Try with timezone
            return datetime.strptime(timestamp.strip(), "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            # Fallback without timezone
            return datetime.strptime(timestamp.strip(), "%d/%b/%Y:%H:%M:%S")

    def detect_brute_force(self, logs):
        failed_logins = defaultdict(list)
        alerts = []
        for log in logs:
            if log['url'] == '/login' and log['status'] == '401':
                ip = log['ip']
                timestamp = self.parse_timestamp(log['timestamp'])
                failed_logins[ip].append(timestamp)

        for ip, timestamps in failed_logins.items():
            recent_attempts = [
                t for t in timestamps if
                (datetime.now() - t).total_seconds() <= self.THRESHOLDS['brute_force']['time_window']
            ]
            if len(recent_attempts) >= self.THRESHOLDS['brute_force']['attempts']:
                alert = f"Brute-force attack detected from IP: {ip}"
                alerts.append(alert)
                logger.warning(alert)

        return alerts

    def detect_ddos(self, logs):
        ip_requests = defaultdict(list)
        alerts = []

        # Organize logs by IP
        for log in logs:
            ip = log['ip']
            timestamp = self.parse_timestamp(log['timestamp'])
            ip_requests[ip].append(timestamp)

        for ip, timestamps in ip_requests.items():
            # Sort timestamps for accurate windowing
            timestamps.sort()
            recent_requests = [
                t for t in timestamps
                if (datetime.now() - t).total_seconds() <= self.THRESHOLDS['ddos']['time_window']
            ]

            # Log debug info for troubleshooting
            logger.debug(f"DDoS Check for IP {ip}: Requests={len(recent_requests)}")

            # Check if the number of requests exceeds the threshold
            if len(recent_requests) >= self.THRESHOLDS['ddos']['requests']:
                alert = f"DDoS attack detected from IP: {ip} with {len(recent_requests)} requests."
                alerts.append(alert)
                logger.warning(alert)

        return alerts

    def detect_sql_injection(self, logs):
        sql_patterns = [
            r"(?i)(' OR '1'='1|--|;|DROP|SELECT|INSERT|DELETE|UNION|%27|%22|%3D|%20OR%20|%20AND%20)",
            r"(?i)(\bOR\b.*=|\bAND\b.*=)"
        ]

        alerts = []
        for log in logs:
            if any(re.search(pattern, log['url']) for pattern in sql_patterns):
                logger.debug(f"SQL Injection detected: {log['url']}")
                alert = f"SQL Injection attempt detected in URL: {log['url']}"
                alerts.append(alert)
                logger.warning(alert)

        return alerts

    def detect_xss(self, logs):
        xss_patterns = [r"(?i)(<script>|<img|javascript:|onerror=)"]
        alerts = []
        for log in logs:
            if any(re.search(pattern, log['url']) for pattern in xss_patterns):
                alert = f"XSS attack attempt detected in URL: {log['url']}"
                alerts.append(alert)
                logger.warning(alert)

        return alerts

    def start_analysis(self):
        try:
            with open(self.log_file, "r") as file:
                file.seek(0, os.SEEK_END)
                while True:
                    new_logs = []
                    for line in file:
                        unique_id = hash(line)
                        if unique_id not in self.processed_logs:
                            self.processed_logs.add(unique_id)
                            log_entry = self.parse_log_entry(line)
                            if log_entry:
                                new_logs.append(log_entry)

                    if new_logs:
                        alerts = (
                                self.detect_brute_force(new_logs) +
                                self.detect_ddos(new_logs) +
                                self.detect_sql_injection(new_logs) +
                                self.detect_xss(new_logs)
                        )
                        for alert in alerts:
                            logger.error(alert)

                    time.sleep(5)
        except Exception as e:
            logger.error(f"Error in start_analysis: {e}")
            print(f"Error in start_analysis: {e}")

    def monitor_resources(self):
        while True:
            cpu_usage = psutil.cpu_percent(interval=self.THRESHOLDS['resource_monitoring_interval'])
            memory_info = psutil.virtual_memory()
            memory_usage = memory_info.percent
            disk_usage = psutil.disk_usage('/').percent
            logger.info(f"Resource Usage: CPU={cpu_usage}%, Memory={memory_usage}%, Disk={disk_usage}%")
            time.sleep(self.THRESHOLDS['resource_monitoring_interval'])
