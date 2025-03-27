import psutil
from celery import shared_task
from django.core.management import call_command
from .models import SystemMetrics
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

@shared_task
def parse_logs_task():
    print('Parsing logs')
    call_command('parse_logs')


# toolkit/tasks.py
@shared_task
def collect_resource_metrics():
    try:
        # Get system metrics
        cpu_usage = psutil.cpu_percent(interval=1)
        ram = psutil.virtual_memory()
        disk = psutil.disk_usage('/')

        # Create new record
        metric = SystemMetrics.objects.create(
            cpu_usage=cpu_usage,
            ram_usage=ram.percent,
            ram_total=ram.total / (1024 * 1024),
            ram_used=ram.used / (1024 * 1024),
            disk_usage=disk.percent,
            disk_total=disk.total / (1024 * 1024 * 1024),
            disk_used=disk.used / (1024 * 1024 * 1024)
        )

        # Delete old records
        newest_ids = SystemMetrics.objects.all() \
                         .order_by('-timestamp') \
                         .values_list('id', flat=True)[:100]
        SystemMetrics.objects.exclude(id__in=newest_ids).delete()

        # Send WebSocket update
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            "resource_updates",
            {
                'type': 'resource.update',
                'timestamp': metric.timestamp.isoformat(),
                'cpu_usage': metric.cpu_usage,
                'ram_usage': metric.ram_usage,
                'ram_total': metric.ram_total,
                'ram_used': metric.ram_used,
                'disk_usage': metric.disk_usage,
                'disk_total': metric.disk_total,
                'disk_used': metric.disk_used,
            }
        )

    except Exception as e:
        print(f"Error collecting metrics: {e}")
        raise