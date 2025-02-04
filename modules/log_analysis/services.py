import json
import re
import os
import time
from datetime import datetime
from loguru import logger
import psutil

thresholds = {
    "resource_monitoring_interval": 5,  # Check every 5 seconds
}

log_dir = "../logs"
log_prefix = "log_analysis_"
log_extension = ".log"


def parse_log_entry(log_entry):
    apache_log = re.compile(
        r'(?P<ip>[\d.]+) - - \[(?P<timestamp>[^\]]+)\s*\] "(?P<method>[A-Z]+) (?P<url>[^"]+) (?P<protocol>[^"]+)" ('
        r'?P<status>\d{3}) (?P<bytes>\d+)( "(?P<user_agent>[^"]+)")?'
    )
    match = apache_log.match(log_entry)
    if match:
        return match.groupdict()
    logger.debug(f"Failed to parse log entry: {log_entry}")
    return None


def parse_timestamp(timestamp):
    try:
        # Try with timezone
        return datetime.strptime(timestamp.strip(), "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        # Fallback without timezone
        return datetime.strptime(timestamp.strip(), "%d/%b/%Y:%H:%M:%S")


def monitor_resources():
    while True:
        cpu_usage = psutil.cpu_percent(interval=thresholds['resource_monitoring_interval'])
        memory_info = psutil.virtual_memory()
        memory_usage = memory_info.percent
        disk_usage = psutil.disk_usage('/').percent
        logger.info(f"Resource Usage: CPU={cpu_usage}%, Memory={memory_usage}%, Disk={disk_usage}%")
        time.sleep(thresholds['resource_monitoring_interval'])

