import os
import re
import json
from datetime import datetime
from django.core.management.base import BaseCommand
from toolkit.models import AlertLogs, SuspiciousLogs, WatchlistLogs, ResourceUsageLogs

# Absolute path to the logs directory
import os
import re
import json
from datetime import datetime
from django.core.management.base import BaseCommand
from toolkit.models import AlertLogs, SuspiciousLogs, WatchlistLogs, ResourceUsageLogs

# Correctly formatted log directory path
log_dir = r"C:\Users\madza\PycharmProjects\IncidentResponseToolkit\modules\logs"
log_prefix = "log_analysis_"
log_extension = ".log"


def get_latest_log_file(log_directory, log_prefix_name, log_suffix):
    if not os.path.exists(log_directory):
        raise FileNotFoundError(f"The log directory '{log_directory}' does not exist.")

    log_files = [
        f for f in os.listdir(log_directory)
        if f.startswith(log_prefix_name) and f.endswith(log_suffix)
    ]

    if not log_files:
        raise FileNotFoundError("No log files found in the directory.")

    # Sort by date extracted from filename (assuming filename format is correct)
    latest_file = max(
        log_files,
        key=lambda f: datetime.strptime(f[len(log_prefix_name):-len(log_suffix)], "%Y%m%d")
    )

    return os.path.join(log_directory, latest_file)


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

                # Check if the message contains structured data
                message = log_entry["message"]
                if "{" in message and "}" in message:
                    json_str = message[message.index("{"): message.rindex("}") + 1]
                    try:
                        structured_data = json.loads(json_str)
                        log_entry["structured_data"] = structured_data
                    except json.JSONDecodeError:
                        log_entry["structured_data"] = None

                logs.append(log_entry)
    return logs


class Command(BaseCommand):
    help = 'Parse log files and insert them into the database'

    def handle(self, *args, **kwargs):
        logs = parse_loguru_logs()
        for log in logs:
            timestamp = datetime.strptime(log['timestamp'], "%Y-%m-%d %H:%M:%S.%f")
            message = log['message']
            level = log['level']
            module = log['module']

            if level == 'ERROR':
                AlertLogs.objects.create(timeStamp=timestamp, message=message)
            elif level == 'WARNING' and module == 'LogAnalysis:log_analysis':
                SuspiciousLogs.objects.create(timeStamp=timestamp, message=message)
            elif level == 'WARNING' and module == 'LogAnalysis:monitor_watchlist':
                WatchlistLogs.objects.create(timeStamp=timestamp, message=message)
            else:
                ResourceUsageLogs.objects.create(timeStamp=timestamp, message=message)

        self.stdout.write(self.style.SUCCESS('Successfully parsed and inserted logs into the database'))
