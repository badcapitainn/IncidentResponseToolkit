from rest_framework import serializers
from .models import SuspiciousLogs, RegularLogs
from django.contrib.auth.models import User


class RegularlogsSerializer(serializers.ModelSerializer):
    class Meta:
        model = RegularLogs
        fields = '__all__'


class SuspiciousLogsSerializer(serializers.ModelSerializer):
    class Meta:
        model = SuspiciousLogs
        fields = '__all__'


