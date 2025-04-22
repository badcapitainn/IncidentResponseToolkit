from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from django.db import models


# models.py
class AlertLogs(models.Model):
    log_Id = models.AutoField(primary_key=True)
    timeStamp = models.DateTimeField()
    message = models.TextField()

    class Meta:
        unique_together = ('timeStamp', 'message')


class SuspiciousLogs(models.Model):
    log_Id = models.AutoField(primary_key=True)
    timeStamp = models.DateTimeField()
    message = models.TextField()

    class Meta:
        unique_together = ('timeStamp', 'message')


class WatchlistLogs(models.Model):
    log_Id = models.AutoField(primary_key=True)
    timeStamp = models.DateTimeField()
    message = models.TextField()

    class Meta:
        unique_together = ('timeStamp', 'message')


class ResourceUsageLogs(models.Model):
    log_Id = models.AutoField(primary_key=True)
    timeStamp = models.DateTimeField()
    message = models.TextField()

    class Meta:
        unique_together = ('timeStamp', 'message')


class SuspiciousPackets(models.Model):
    log_Id = models.AutoField(primary_key=True)
    timeStamp = models.DateTimeField()
    message = models.TextField()
    source_ip = models.CharField(max_length=15, default='N/A')
    risk_level = models.CharField(max_length=10, choices=[
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High')
    ], default='low')

    class Meta:
        unique_together = ('timeStamp', 'message')
        verbose_name_plural = 'Suspicious Packets'

    def __str__(self):
        return f"Suspicious packet at {self.timeStamp}"


class MaliciousPackets(models.Model):
    log_Id = models.AutoField(primary_key=True)
    timeStamp = models.DateTimeField()
    message = models.TextField()
    source_ip = models.CharField(max_length=15, default='N/A')
    threat_type = models.CharField(max_length=50, choices=[
        ('ddos', 'DDoS Attack'),
        ('sql_injection', 'SQL Injection'),
        ('exploit', 'Exploit Attempt'),
        ('xss', 'XSS Attack'),
        ('brute_force', 'Brute Force Attempt'),
        ('other', 'Malicious Activity')
    ], default='other')

    class Meta:
        unique_together = ('timeStamp', 'message')
        verbose_name_plural = 'Malicious Packets'

    def __str__(self):
        return f"Malicious packet at {self.timeStamp}"


class SystemMetrics(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    cpu_usage = models.FloatField()  # percentage
    ram_used = models.FloatField()  # in MB
    disk_read = models.FloatField()  # in MB
    disk_write = models.FloatField()  # in MB
    is_application_only = models.BooleanField(default=False)

    class Meta:
        ordering = ['-timestamp']


class MalwareDetectionResult(models.Model):
    SCAN_TYPES = (
        ('FILE', 'File Scan'),
        ('DIR', 'Directory Scan'),
        ('MEM', 'Memory Scan'),
    )

    file_path = models.CharField(max_length=512)
    scan_time = models.DateTimeField()
    is_malicious = models.BooleanField(default=False)
    malware_type = models.CharField(max_length=255, blank=True, null=True)
    details = models.TextField(blank=True, null=True)
    scan_type = models.CharField(max_length=4, choices=SCAN_TYPES, default='FILE')
    detected_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)

    class Meta:
        ordering = ['-scan_time']

    def __str__(self):
        return f"{self.file_path} - {self.malware_type if self.is_malicious else 'Clean'}"