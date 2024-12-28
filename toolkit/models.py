from django.db import models
from django.contrib.auth.models import User


class RegularLogs(models.Model):
    log_ID = models.IntegerField(primary_key=True)
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField()
    method = models.CharField(max_length=50)
    url = models.CharField()
    protocol = models.CharField(max_length=50)
    status = models.CharField(max_length=50)
    bytes_sent = models.IntegerField()


class SuspiciousLogs(models.Model):
    log_ID = models.IntegerField(primary_key=True)
    timestamp = models.DateTimeField()
    alert_type = models.CharField(max_length=50)
    threat_type = models.CharField(max_length=50)
    ip_address = models.GenericIPAddressField()
    message = models.CharField()
