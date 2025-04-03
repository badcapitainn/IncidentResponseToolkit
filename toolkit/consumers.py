import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from .models import AlertLogs, SuspiciousLogs, WatchlistLogs, ResourceUsageLogs, SystemMetrics


class LogConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        await self.channel_layer.group_add("logs", self.channel_name)

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard("logs", self.channel_name)

    async def receive(self, text_data):
        # Handle incoming messages (if needed)
        pass

    async def log_message(self, event):
        # Ensure the log_type key exists in the event
        if 'log_type' not in event:
            return  # Skip if log_type is missing

        # Send the updated logs to the client
        log_type = event['log_type']
        logs = await self.get_logs(log_type)
        await self.send(text_data=json.dumps({
            'log_type': log_type,
            'logs': logs,
        }))

    @database_sync_to_async
    def get_logs(self, log_type):
        # Fetch logs from the database based on the log type
        if log_type == 'alert':
            logs = AlertLogs.objects.values('timeStamp', 'message')
        elif log_type == 'suspicious':
            logs = SuspiciousLogs.objects.values('timeStamp', 'message')
        elif log_type == 'watchlist':
            logs = WatchlistLogs.objects.values('timeStamp', 'message')
        elif log_type == 'resource':
            logs = ResourceUsageLogs.objects.values('timeStamp', 'message')
        else:
            return []

        # Convert datetime objects to strings
        logs_list = list(logs)
        for log in logs_list:
            log['timeStamp'] = log['timeStamp'].isoformat()  # Convert datetime to ISO format string
        return logs_list


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


class NetworkAnalysisConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.channel_layer.group_add(
            "network_analysis",
            self.channel_name
        )
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            "network_analysis",
            self.channel_name
        )

    async def network_message(self, event):
        await self.send(text_data=json.dumps(event))

    async def packet_update(self, event):
        await self.send(text_data=json.dumps({
            'type': 'packet.update',
            'packet': event['packet']
        }))