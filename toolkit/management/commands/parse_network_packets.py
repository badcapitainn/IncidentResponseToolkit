import os
import re
from datetime import datetime
from django.core.management.base import BaseCommand
from django.utils import timezone
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from toolkit.models import SuspiciousPackets, MaliciousPackets


class Command(BaseCommand):
    help = 'Parse network packet logs and store them in the database'

    def add_arguments(self, parser):
        parser.add_argument(
            '--log-file',
            type=str,
            default='C:\\Users\\madza\\PycharmProjects\\IncidentResponseToolkit\\modules\\network_analysis\\network_analysis.log',
            help='Path to the network analysis log file'
        )
        parser.add_argument(
            '--continuous',
            action='store_true',
            help='Run in continuous monitoring mode'
        )

    def handle(self, *args, **options):
        self.log_file_path = options['log_file']
        self.continuous = options['continuous']
        self.channel_layer = get_channel_layer()

        if not os.path.exists(self.log_file_path):
            self.stdout.write(self.style.ERROR(f'Log file not found at {self.log_file_path}'))
            return

        if self.continuous:
            self.stdout.write(self.style.SUCCESS('Starting continuous log monitoring...'))
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler
            import time

            class LogFileHandler(FileSystemEventHandler):
                def __init__(self, command):
                    self.command = command
                    self.last_position = 0

                def on_modified(self, event):
                    if event.src_path == self.command.log_file_path:
                        self.command.process_new_lines()

            event_handler = LogFileHandler(self)
            observer = Observer()
            observer.schedule(event_handler, os.path.dirname(self.log_file_path))
            observer.start()

            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                observer.stop()
            observer.join()
        else:
            self.process_file()

    def process_file(self, from_position=0):
        try:
            with open(self.log_file_path, 'r') as file:
                if from_position > 0:
                    file.seek(from_position)

                for line in file:
                    self.parse_line(line)

                return file.tell()
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error processing file: {e}'))
            return from_position

    def process_new_lines(self):
        current_size = os.path.getsize(self.log_file_path)
        if not hasattr(self, 'last_file_position'):
            self.last_file_position = 0

        if current_size < self.last_file_position:
            # File was rotated/truncated
            self.last_file_position = 0

        self.last_file_position = self.process_file(self.last_file_position)

    def parse_line(self, line):
        # Skip empty lines
        if not line.strip():
            return

        # Parse timestamp with multiple format support
        timestamp = self.parse_timestamp(line)
        if not timestamp:
            return

        # Check if line contains packet information
        packet_match = re.search(r'\[(NORMAL|MALICIOUS|WARNING)\] Sent packet: (.+)$', line)
        if not packet_match:
            return

        packet_type = packet_match.group(1)
        message = packet_match.group(2).strip()

        try:
            if packet_type in ['MALICIOUS', 'WARNING']:
                self.handle_malicious_packet(timestamp, message)
            elif packet_type == 'NORMAL' and self.is_suspicious(message):
                self.handle_suspicious_packet(timestamp, message)

        except Exception as e:
            self.stdout.write(self.style.WARNING(f'Error processing line: {e}'))

    def parse_timestamp(self, line):
        """Parse timestamp from log line with support for multiple formats"""
        timestamp_match = re.search(
            r'(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\+\d{4})?)',
            line
        )
        if not timestamp_match:
            return None

        timestamp_str = timestamp_match.group('timestamp')

        try:
            # Try ISO format first (with 'T' separator)
            if 'T' in timestamp_str:
                if '+' in timestamp_str:  # With timezone
                    timestamp_str = timestamp_str.split('+')[0]
                try:
                    timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f")
                except ValueError:
                    timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
            else:
                # Try space-separated format
                if '.' in timestamp_str:  # With microseconds
                    timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.%f")
                else:
                    timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")

            return timezone.make_aware(timestamp)
        except ValueError as e:
            self.stdout.write(self.style.WARNING(f'Could not parse timestamp "{timestamp_str}": {e}'))
            return None

    def handle_malicious_packet(self, timestamp, message):
        if not MaliciousPackets.objects.filter(timeStamp=timestamp, message=message).exists():
            packet = MaliciousPackets.objects.create(
                timeStamp=timestamp,
                message=message,
                threat_type=self.detect_threat_type(message),
                source_ip=self.extract_ip(message)
            )
            self.send_websocket_update('malicious', packet)

    def handle_suspicious_packet(self, timestamp, message):
        if not SuspiciousPackets.objects.filter(timeStamp=timestamp, message=message).exists():
            packet = SuspiciousPackets.objects.create(
                timeStamp=timestamp,
                message=message,
                risk_level=self.detect_risk_level(message),
                source_ip=self.extract_ip(message)
            )
            self.send_websocket_update('suspicious', packet)

    def send_websocket_update(self, packet_type, packet):
        async_to_sync(self.channel_layer.group_send)(
            "network_packets",
            {
                'type': 'packet.update',
                'packet_type': packet_type,
                'message': {
                    'id': packet.log_Id,
                    'timestamp': packet.timeStamp.isoformat(),
                    'message': packet.message,
                    'source_ip': packet.source_ip,
                    'destination_ip': 'N/A',
                    'threat_type': getattr(packet, 'threat_type', None),
                    'risk_level': getattr(packet, 'risk_level', None)
                }
            }
        )

    def is_suspicious(self, message):
        """Determine if a packet is suspicious based on its content"""
        suspicious_patterns = [
            r'user[\s_-]?login', r'ping', r'GET /', r'HTTP/',
            r'login request', r'session', r'cookie', r'token',
            r'exploit', r'injection', r'attack'
        ]
        return any(re.search(pattern, message, re.IGNORECASE) for pattern in suspicious_patterns)

    def detect_threat_type(self, message):
        """Determine the type of threat based on message content"""
        message_lower = message.lower()
        if 'ddos' in message_lower:
            return 'ddos'
        elif 'sql_injection' in message_lower or 'sql injection' in message_lower:
            return 'sql_injection'
        elif 'exploit' in message_lower:
            return 'exploit'
        elif 'xss' in message_lower:
            return 'xss'
        elif 'brute force' in message_lower:
            return 'brute_force'
        return 'other'

    def detect_risk_level(self, message):
        """Determine risk level for suspicious packets"""
        message_lower = message.lower()
        if any(x in message_lower for x in ['login', 'auth', 'authenticate', 'password']):
            return 'high'
        elif any(x in message_lower for x in ['get', 'post', 'http', 'request']):
            return 'medium'
        return 'low'

    def extract_ip(self, message):
        """Extract IP address from message if present"""
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', message)
        return ip_match.group(0) if ip_match else 'N/A'
