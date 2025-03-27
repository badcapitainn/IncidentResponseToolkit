import os
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


@shared_task
def collect_resource_metrics():
    try:
        current_process = psutil.Process(os.getpid())

        # Get metrics
        cpu_percent = current_process.cpu_percent(interval=1)
        mem_info = current_process.memory_info()
        ram_used = mem_info.rss / (1024 * 1024)  # MB
        io_counters = current_process.io_counters()
        disk_read = io_counters.read_bytes / (1024 * 1024)  # MB
        disk_write = io_counters.write_bytes / (1024 * 1024)  # MB

        # Create record
        metric = SystemMetrics.objects.create(
            cpu_usage=cpu_percent,
            ram_used=ram_used,
            disk_read=disk_read,
            disk_write=disk_write,
            is_application_only=True
        )

        # Clean up old records
        newest_ids = SystemMetrics.objects.filter(is_application_only=True) \
                         .order_by('-timestamp') \
                         .values_list('id', flat=True)[:100]
        SystemMetrics.objects.filter(is_application_only=True) \
            .exclude(id__in=newest_ids) \
            .delete()

        # Send WebSocket update
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            "resources",
            {
                'type': 'resource.update',
                'timestamp': metric.timestamp.isoformat(),
                'cpu_usage': metric.cpu_usage,
                'ram_used': metric.ram_used,
                'disk_read': metric.disk_read,
                'disk_write': metric.disk_write,
            }
        )

    except Exception as e:
        print(f"Error collecting metrics: {e}")
        raise