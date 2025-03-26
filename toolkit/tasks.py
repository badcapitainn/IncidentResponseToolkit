import psutil
from celery import shared_task
from django.core.management import call_command
from .models import SystemMetrics


@shared_task
def parse_logs_task():
    print('Parsing logs')
    call_command('parse_logs')


# toolkit/tasks.py
@shared_task
def collect_resource_metrics():
    try:
        # Get system metrics (your existing code)
        cpu_usage = psutil.cpu_percent(interval=1)
        ram = psutil.virtual_memory()
        disk = psutil.disk_usage('/')

        # Create new record
        SystemMetrics.objects.create(
            cpu_usage=cpu_usage,
            ram_usage=ram.percent,
            ram_total=ram.total / (1024 * 1024),  # Convert to MB
            ram_used=ram.used / (1024 * 1024),  # Convert to MB
            disk_usage=disk.percent,
            disk_total=disk.total / (1024 * 1024 * 1024),  # Convert to GB
            disk_used=disk.used / (1024 * 1024 * 1024)  # Convert to GB
        )

        # Delete old records (keep only last 100)
        # Get IDs of the newest 100 records
        newest_ids = SystemMetrics.objects.all() \
                         .order_by('-timestamp') \
                         .values_list('id', flat=True)[:100]

        # Delete all records except those in newest_ids
        SystemMetrics.objects.exclude(id__in=newest_ids).delete()

    except Exception as e:
        print(f"Error collecting metrics: {e}")
        raise