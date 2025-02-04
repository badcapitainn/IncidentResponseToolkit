import os
import re
import time
from datetime import datetime, timedelta
from collections import defaultdict, deque
from loguru import logger
import psutil
import numpy as np
from sklearn.ensemble import IsolationForest
from services import parse_log_entry, parse_timestamp, monitor_resources


class LogAnalysis:

    # Configurations
    THRESHOLDS = {
        "brute_force": {"attempts": 5, "time_window": 300},  # 5 attempts in 5 minutes
        "ddos": {"requests": 50, "time_window": 10},  # 50 requests in 10 seconds
        "anomaly_detection_interval": 60,  # Check for anomalies every 60 seconds
        "watchlist_monitoring_interval": 10,  # Monitor watchlist every 10 seconds
        "watchlist_threshold": 3,  # Number of anomalies to add an IP to the watchlist
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
        self.anomaly_detector = IsolationForest(contamination=0.01)
        self.log_buffer = deque(maxlen=1000)  # Buffer to store recent logs
        self.watchlist = defaultdict(int)  # Tracks suspicious IPs and their anomaly counts
        self.blocked_ips = {}  # Tracks blocked IPs and their unblock times

    def detect_brute_force(self, logs):
        failed_logins = defaultdict(list)
        alerts = []
        current_time = datetime.now()

        for log in logs:
            if log['url'] == '/login' and log['status'] == '401':
                ip = log['ip']
                timestamp = parse_timestamp(log['timestamp'])
                failed_logins[ip].append(timestamp)

        for ip, timestamps in failed_logins.items():
            # Filter timestamps within the time window
            recent_attempts = [
                t for t in timestamps
                if (current_time - t).total_seconds() <= self.THRESHOLDS['brute_force']['time_window']
            ]
            if len(recent_attempts) >= self.THRESHOLDS['brute_force']['attempts']:
                alert = f"Brute-force attack detected from IP: {ip}"
                alerts.append(alert)
                self.watchlist[ip] += 1  # Add IP to watchlist

        return alerts

    def detect_ddos(self, logs):
        ip_requests = defaultdict(list)
        alerts = []
        current_time = datetime.now()

        for log in logs:
            ip = log['ip']
            timestamp = parse_timestamp(log['timestamp'])
            ip_requests[ip].append(timestamp)

        for ip, timestamps in ip_requests.items():
            # Filter timestamps within the time window
            recent_requests = [
                t for t in timestamps
                if (current_time - t).total_seconds() <= self.THRESHOLDS['ddos']['time_window']
            ]
            if len(recent_requests) >= self.THRESHOLDS['ddos']['requests']:
                alert = f"DDoS attack detected from IP: {ip} with {len(recent_requests)} requests."
                alerts.append(alert)
                self.watchlist[ip] += 1  # Add IP to watchlist

        return alerts

    def detect_sql_injection(self, logs):
        sql_patterns = [
            r"(?i)(' OR '1'='1|--|;|DROP|SELECT|INSERT|DELETE|UNION|%27|%22|%3D|%20OR%20|%20AND%20)",
            r"(?i)(\bOR\b.*=|\bAND\b.*=)"
        ]

        alerts = []
        for log in logs:
            if any(re.search(pattern, log['url']) for pattern in sql_patterns):
                alert = f"SQL Injection attempt detected in URL: {log['url']} from IP: {log['ip']}"
                alerts.append(alert)
                self.watchlist[log['ip']] += 1  # Add IP to watchlist

        return alerts

    def detect_xss(self, logs):
        xss_patterns = [r"(?i)(<script>|<img|javascript:|onerror=)"]
        alerts = []
        for log in logs:
            if any(re.search(pattern, log['url']) for pattern in xss_patterns):
                alert = f"XSS attack attempt detected in URL: {log['url']} from IP: {log['ip']}"
                alerts.append(alert)
                self.watchlist[log['ip']] += 1  # Add IP to watchlist

        return alerts

    def detect_directory_traversal(self, logs):
        traversal_patterns = [r"(?i)(\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c)"]
        alerts = []
        for log in logs:
            if any(re.search(pattern, log['url']) for pattern in traversal_patterns):
                alert = f"Directory traversal attempt detected in URL: {log['url']} from IP: {log['ip']}"
                alerts.append(alert)
                self.watchlist[log['ip']] += 1  # Add IP to watchlist

        return alerts

    def detect_command_injection(self, logs):
        command_patterns = [r"(?i)(;|\||&|`|\$\(|\n)"]
        alerts = []
        for log in logs:
            if any(re.search(pattern, log['url']) for pattern in command_patterns):
                alert = f"Command injection attempt detected in URL: {log['url']} from IP: {log['ip']}"
                alerts.append(alert)
                self.watchlist[log['ip']] += 1  # Add IP to watchlist

        return alerts

    def detect_anomalies(self, logs, batch_size=100):
        alerts = []
        total_logs = len(logs)

        for i in range(0, total_logs, batch_size):
            batch = logs[i:i + batch_size]
            batch_features = []

            for log in batch:
                batch_features.append([
                    len(log['url']),  # URL length
                    int(log['status']),  # Status code
                    int(log['bytes']),  # Response size
                    log['method'] == 'POST',  # Is it a POST request?
                    log['method'] == 'GET',  # Is it a GET request?
                ])

            if batch_features:
                batch_features = np.array(batch_features)
                self.anomaly_detector.fit(batch_features)
                predictions = self.anomaly_detector.predict(batch_features)
                batch_anomalies = np.where(predictions == -1)[0]

                for idx in batch_anomalies:
                    alert = f"Anomalous traffic detected: {batch[idx]}"
                    alerts.append(alert)
                    self.watchlist[batch[idx]['ip']] += 1  # Add IP to watchlist

        return alerts

    def monitor_watchlist(self):
        while True:
            for ip, count in list(self.watchlist.items()):
                if count >= self.THRESHOLDS['watchlist_threshold']:
                    logger.warning(f"IP {ip} is under close watch due to {count} anomalies.")

                    # Additional monitoring logic
                    self.monitor_suspicious_ip(ip)

            time.sleep(self.THRESHOLDS['watchlist_monitoring_interval'])

    def monitor_suspicious_ip(self, ip):
        """
        Monitor a suspicious IP address for further malicious activity.
        """
        # Log detailed activity for the suspicious IP
        recent_activity = [log for log in self.log_buffer if log['ip'] == ip]
        if recent_activity:
            logger.info(f"Recent activity from suspicious IP {ip}:")
            for log in recent_activity:
                logger.info(f"- {log['timestamp']}: {log['method']} {log['url']} ({log['status']})")

        # Rate limiting: Check if the IP is making too many requests
        request_count = len(recent_activity)
        if request_count > self.THRESHOLDS['ddos']['requests']:
            logger.warning(
                f"IP {ip} is making too many requests ({request_count} in the last {self.THRESHOLDS['ddos']['time_window']} seconds).")
            self.block_ip_temporarily(ip)

        # Check for repeated failed login attempts
        failed_logins = [log for log in recent_activity if log['url'] == '/login' and log['status'] == '401']
        if len(failed_logins) >= self.THRESHOLDS['brute_force']['attempts']:
            logger.warning(
                f"IP {ip} has repeated failed login attempts ({len(failed_logins)} in the last {self.THRESHOLDS['brute_force']['time_window']} seconds).")
            self.block_ip_temporarily(ip)

    def block_ip_temporarily(self, ip, block_duration=300):
        """
        Temporarily block an IP address for a specified duration (default: 5 minutes).
        """
        if ip not in self.blocked_ips:
            logger.warning(f"Blocking IP {ip} for {block_duration} seconds.")
            self.blocked_ips[ip] = time.time() + block_duration

    def is_ip_blocked(self, ip):
        """
        Check if an IP address is currently blocked.
        """
        if ip in self.blocked_ips:
            if time.time() < self.blocked_ips[ip]:
                return True
            else:
                # Unblock the IP if the block duration has expired
                del self.blocked_ips[ip]
        return False

    def log_analysis(self):
        try:
            with open(self.log_file, "r") as file:
                file.seek(0, os.SEEK_END)
                while True:
                    new_logs = []
                    for line in file:
                        unique_id = hash(line)
                        if unique_id not in self.processed_logs:
                            self.processed_logs.add(unique_id)
                            log_entry = parse_log_entry(line)
                            if log_entry:
                                new_logs.append(log_entry)
                                self.log_buffer.append(log_entry)

                    if new_logs:
                        alerts = (
                                self.detect_brute_force(new_logs) +
                                self.detect_ddos(new_logs) +
                                self.detect_sql_injection(new_logs) +
                                self.detect_xss(new_logs) +
                                self.detect_directory_traversal(new_logs) +
                                self.detect_command_injection(new_logs)
                        )
                        warnings = (
                            self.detect_anomalies(new_logs)
                        )
                        for alert in alerts:
                            logger.error(alert)
                        for warning in warnings:
                            logger.warning(warning)

                    time.sleep(5)
        except Exception as e:
            logger.error(f"Error in start_analysis: {e}")
            print(f"Error in start_analysis: {e}")

    def run(self):
        import threading
        # Start log analysis in a separate thread
        analysis_thread = threading.Thread(target=self.log_analysis)
        analysis_thread.daemon = True
        analysis_thread.start()

        # Start resource monitoring in a separate thread
        resource_thread = threading.Thread(target= monitor_resources)
        resource_thread.daemon = True
        resource_thread.start()

        # Start watchlist monitoring in a separate thread
        watchlist_thread = threading.Thread(target=self.monitor_watchlist)
        watchlist_thread.daemon = True
        watchlist_thread.start()

        # Keep the main thread alive
        while True:
            time.sleep(1)
