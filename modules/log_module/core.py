import os
import gzip
import re
from datetime import datetime, timedelta
from collections import defaultdict
import loguru
from django.conf import settings
from toolkit.models import LogEntry, LogSource, LogAlert
from modules.firewall.blocker import FirewallBlocker


class LogAnalyzer:
    def __init__(self):
        self.logger = loguru.logger
        self.retention_days = 30

        self.compression_enabled = True
        self.alert_thresholds = {
            'ERROR': 5,
            'WARNING': 10,
            'CRITICAL': 1
        }
        self.current_alerts = []
        self.configure_logger()
        self._firewall = None

    @property
    def firewall(self):
        if self._firewall is None:
            self._firewall = FirewallBlocker()
        return self._firewall

    def configure_logger(self):
        self.logger.add(
            os.path.join(settings.LOGS_DIR, "log_analysis_{time}.log"),
            rotation="10 MB",
            retention=f"{self.retention_days} days",
            compression="zip" if self.compression_enabled else None,
            level="INFO"
        )

    def process_log_file(self, file_path, source_name="system"):
        """Process a log file line by line"""
        try:
            # Check if file is gzipped
            is_gzipped = file_path.endswith('.gz')

            opener = gzip.open if is_gzipped else open
            mode = 'rt' if is_gzipped else 'r'

            with opener(file_path, mode) as f:
                for line in f:
                    self.process_log_line(line.strip(), source_name)

            self.check_for_alerts()
            return True
        except Exception as e:
            self.logger.error(f"Error processing log file {file_path}: {str(e)}")
            return False

    def process_log_line(self, line, source_name):
        """Parse and process a single log line"""
        if not line:
            return

        # Basic log parsing (can be extended for different log formats)
        try:
            # Common log format: [timestamp] [level] message
            match = re.match(r'\[(.*?)\] \[(.*?)\] (.*)', line)
            if match:
                timestamp_str, level, message = match.groups()
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            else:
                # Fallback for other formats
                timestamp = datetime.now()
                level = "INFO"
                message = line

            # Save to database
            log_entry = LogEntry.objects.create(
                timestamp=timestamp,
                level=level,
                message=message,
                source=LogSource.objects.get_or_create(name=source_name)[0]
            )

            # Check for immediate alerts
            if level in ['ERROR', 'CRITICAL']:
                self.current_alerts.append({
                    'timestamp': timestamp,
                    'level': level,
                    'message': message,
                    'source': source_name
                })

            return log_entry
        except Exception as e:
            self.logger.error(f"Error processing log line: {line}. Error: {str(e)}")
            return None

    def check_for_alerts(self):
        """Check collected logs for alert conditions and block IPs if needed"""
        # Group alerts by type and source IP
        alert_counts = defaultdict(int)
        ip_alert_counts = defaultdict(lambda: defaultdict(int))

        for alert in self.current_alerts:
            alert_counts[alert['level']] += 1
            if 'ip' in alert:  # Extract IP from alert if available
                ip_alert_counts[alert['ip']][alert['level']] += 1

        # Check against thresholds
        for level, threshold in self.alert_thresholds.items():
            if alert_counts.get(level, 0) >= threshold:
                self.create_alert(
                    level=level,
                    message=f"Excessive {level} logs detected: {alert_counts[level]} occurrences",
                    details="\n".join([a['message'] for a in self.current_alerts if a['level'] == level])
                )

        # Check for IPs to block
        for ip, counts in ip_alert_counts.items():
            if counts.get('CRITICAL', 0) >= 3 or counts.get('ERROR', 0) >= 10:
                self.firewall.block_ip(
                    ip_address=ip,
                    reason=f"Excessive {level} events from this IP",
                    duration_minutes=120
                )
                self.create_alert(
                    level='CRITICAL',
                    message=f"Blocked IP {ip} due to malicious activity",
                    details=f"Blocked after {counts} suspicious events"
                )

        self.current_alerts = []

    def create_alert(self, level, message, details=""):
        """Create a new alert in the database"""
        LogAlert.objects.create(
            level=level,
            message=message,
            details=details,
            timestamp=datetime.now()
        )
        self.logger.warning(f"ALERT: {message}")

    def compress_old_logs(self):
        """Compress logs older than 7 days"""
        cutoff = datetime.now() - timedelta(days=7)
        old_logs = LogEntry.objects.filter(timestamp__lt=cutoff, compressed=False)

        for log in old_logs:
            try:
                # In a real implementation, you'd compress the log content here
                log.compressed = True
                log.save()
            except Exception as e:
                self.logger.error(f"Error compressing log {log.id}: {str(e)}")

    def get_log_statistics(self):
        """Generate statistics about logs"""
        stats = {
            'total_logs': LogEntry.objects.count(),
            'levels': {},
            'sources': {},
            'recent_alerts': LogAlert.objects.filter(
                timestamp__gte=datetime.now() - timedelta(hours=24)
            ).count()
        }

        # Count by level
        for level in LogEntry.LEVEL_CHOICES:
            stats['levels'][level[0]] = LogEntry.objects.filter(level=level[0]).count()

        # Count by source
        for source in LogSource.objects.all():
            stats['sources'][source.name] = LogEntry.objects.filter(source=source).count()

        return stats