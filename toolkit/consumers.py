# toolkit/consumers.py

import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from .models import AlertLogs, SuspiciousLogs, WatchlistLogs, ResourceUsageLogs


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
