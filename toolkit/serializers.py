from rest_framework import serializers
from .models import SuspiciousLogs, AlertLogs, WatchlistLogs


class SuspiciousLogsSerializer(serializers.ModelSerializer):
    class Meta:
        model = SuspiciousLogs
        fields = '__all__'


class AlertLogsSerializer(serializers.ModelSerializer):
    class Meta:
        model = AlertLogs
        fields = '__all__'


class WatchlistLogsSerializer(serializers.ModelSerializer):
    class Meta:
        model = WatchlistLogs
        fields = '__all__'
