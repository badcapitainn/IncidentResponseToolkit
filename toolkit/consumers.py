import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from .models import AlertLogs, SuspiciousLogs, WatchlistLogs, ResourceUsageLogs, SystemMetrics


class ResourceConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        await self.channel_layer.group_add("resources", self.channel_name)
        await self.send_initial_data()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard("resources", self.channel_name)

    @database_sync_to_async
    def get_latest_metrics(self):
        latest = SystemMetrics.objects.filter(is_application_only=True).last()
        if latest:
            return {
                'type': 'resource.update',
                'timestamp': latest.timestamp.isoformat(),
                'cpu_usage': latest.cpu_usage,
                'ram_used': latest.ram_used,
                'disk_read': latest.disk_read,
                'disk_write': latest.disk_write,
            }
        return None

    async def send_initial_data(self):
        data = await self.get_latest_metrics()
        if data:
            await self.send(text_data=json.dumps(data))

    async def resource_update(self, event):
        await self.send(text_data=json.dumps(event))


