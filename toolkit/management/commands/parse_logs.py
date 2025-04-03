import os
import re
from datetime import datetime
from django.core.management.base import BaseCommand
from toolkit.models import AlertLogs, SuspiciousLogs, WatchlistLogs, ResourceUsageLogs
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from django.utils import timezone

log_dir = r"C:\Users\madza\PycharmProjects\IncidentResponseToolkit\modules\logs"
log_prefix = "log_analysis_"
log_extension = ".log"


def get_latest_log_file(log_directory, log_prefix_name, log_suffix):
    log_files = [
        f for f in os.listdir(log_dir)
        if f.startswith(log_prefix) and f.endswith(log_extension)
    ]

    if not log_files:
        raise FileNotFoundError("No log files found in the directory.")

    latest_file = max(
        log_files,
        key=lambda f: datetime.strptime(f[len(log_prefix):-len(log_extension)], "%Y%m%d")
    )

    return os.path.join(log_dir, latest_file)


def parse_loguru_logs():
    log_pattern = (
        r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})"  # Timestamp
        r" \| (?P<level>[A-Z]+) *\|"  # Log Level
        r" (?P<module>[\w:]+):(?P<line_number>\d+) -"  # Module and line number
        r" (?P<message>.+)"  # Log message
    )
    latest_log_file = get_latest_log_file(log_dir, log_prefix, log_extension)

    logs = []

    with open(latest_log_file, "r") as file:
        for line in file:
            match = re.match(log_pattern, line)
            if match:
                log_entry = match.groupdict()
                logs.append(log_entry)
    return logs


class Command(BaseCommand):
    help = 'Parse log files and insert them into the database'

    def handle(self, *args, **kwargs):
        logs = parse_loguru_logs()
        channel_layer = get_channel_layer()  # Get the channel layer

        for log in logs:
            timestamp = timezone.make_aware(datetime.strptime(log['timestamp'], "%Y-%m-%d %H:%M:%S.%f"))
            message = log['message']
            level = log['level']
            module = log['module']

            try:
                if level == 'CRITICAL' and not AlertLogs.objects.filter(timeStamp=timestamp, message=message).exists():
                    AlertLogs.objects.create(timeStamp=timestamp, message=message)
                    # Trigger WebSocket update for alert logs
                    async_to_sync(channel_layer.group_send)(
                        "logs",
                        {
                            'type': 'log_message',
                            'log_type': 'alert',
                        }
                    )

                elif level == 'WARNING' and not SuspiciousLogs.objects.filter(message=message).exists():
                    SuspiciousLogs.objects.create(timeStamp=timestamp, message=message)
                    # Trigger WebSocket update for suspicious logs
                    async_to_sync(channel_layer.group_send)(
                        "logs",
                        {
                            'type': 'log_message',
                            'log_type': 'suspicious',
                        }
                    )

                elif level == 'ERROR' and not WatchlistLogs.objects.filter(message=message).exists():
                    WatchlistLogs.objects.create(timeStamp=timestamp, message=message)
                    # Trigger WebSocket update for watchlist logs
                    async_to_sync(channel_layer.group_send)(
                        "logs",
                        {
                            'type': 'log_message',
                            'log_type': 'watchlist',
                        }
                    )

            except Exception as e:
                self.stdout.write(self.style.ERROR(f'Error processing log entry: {e}'))

        self.stdout.write(self.style.SUCCESS('Successfully parsed and inserted logs into the database'))
