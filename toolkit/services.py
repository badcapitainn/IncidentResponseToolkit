import psutil
from .models import SystemMetrics


def collect_metrics():
    """Collect system metrics and save to database"""
    cpu = psutil.cpu_percent(interval=1)
    ram = psutil.virtual_memory()
    disk = psutil.disk_usage('/')

    SystemMetrics.objects.create(
        cpu_usage=cpu,
        ram_usage=ram.percent,
        ram_used=ram.used / (1024 ** 3),  # Convert to GB
        ram_total=ram.total / (1024 ** 3),
        disk_usage=disk.percent,
        disk_used=disk.used / (1024 ** 3),
        disk_total=disk.total / (1024 ** 3)
    )