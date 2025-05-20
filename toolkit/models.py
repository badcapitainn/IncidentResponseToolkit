from datetime import timedelta
from django.utils import timezone

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

    # Add to toolkit/models.py


class Quarantine(models.Model):
    original_path = models.CharField(max_length=512)
    quarantine_path = models.CharField(max_length=512)
    quarantine_time = models.DateTimeField(auto_now_add=True)
    detection_result = models.ForeignKey(MalwareDetectionResult, on_delete=models.CASCADE)
    restored = models.BooleanField(default=False)
    restored_time = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.original_path} (Quarantined)"


# ----------------------------------------------- network analysis test -----------------------------------------------

class NetworkCapture(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    start_time = models.DateTimeField(auto_now_add=True)
    end_time = models.DateTimeField(null=True, blank=True)
    packet_count = models.IntegerField(default=0)
    capture_file = models.FilePathField(path='captures/', max_length=255, default='')
    is_active = models.BooleanField(default=False)

    def __str__(self):
        return f"Capture {self.id} by {self.user.username}"


class NetworkAlert(models.Model):
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('in_progress', 'In Progress'),
        ('resolved', 'Resolved'),
        ('false_positive', 'False Positive')
    ]

    capture = models.ForeignKey(NetworkCapture, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)
    rule_id = models.CharField(max_length=50)
    rule_name = models.CharField(max_length=100)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    src_ip = models.GenericIPAddressField(null=True, blank=True)
    dst_ip = models.GenericIPAddressField(null=True, blank=True)
    protocol = models.CharField(max_length=10, null=True, blank=True)
    src_port = models.IntegerField(null=True, blank=True)
    dst_port = models.IntegerField(null=True, blank=True)
    packet_size = models.IntegerField(null=True, blank=True)
    details = models.JSONField(default=dict)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    resolution = models.TextField(blank=True, null=True)
    resolved_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    resolved_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.rule_name} alert at {self.timestamp}"


class NetworkRule(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField()
    condition = models.TextField()
    severity = models.CharField(max_length=10, choices=NetworkAlert.SEVERITY_CHOICES)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


# ---------------------------------------------------log analysis models -----------------------------------------------

class LogSource(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class LogEntry(models.Model):
    LEVEL_CHOICES = [
        ('DEBUG', 'Debug'),
        ('INFO', 'Info'),
        ('WARNING', 'Warning'),
        ('ERROR', 'Error'),
        ('CRITICAL', 'Critical'),
    ]

    timestamp = models.DateTimeField()
    level = models.CharField(max_length=10, choices=LEVEL_CHOICES)
    message = models.TextField()
    source = models.ForeignKey(LogSource, on_delete=models.CASCADE)
    compressed = models.BooleanField(default=False)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['level']),
        ]

    def __str__(self):
        return f"{self.timestamp} [{self.level}] {self.message[:50]}..."


class LogAlert(models.Model):
    LEVEL_CHOICES = LogEntry.LEVEL_CHOICES

    timestamp = models.DateTimeField(auto_now_add=True)
    level = models.CharField(max_length=10, choices=LEVEL_CHOICES)
    message = models.TextField()
    details = models.TextField(blank=True)
    resolved = models.BooleanField(default=False)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.timestamp} [{self.level}] {self.message[:50]}..."

    def resolve(self, user):
        self.resolved = True
        self.resolved_at = timezone.now()
        self.resolved_by = user
        self.save()


class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    blocked_at = models.DateTimeField(auto_now_add=True)
    reason = models.TextField()
    duration_minutes = models.IntegerField(default=60)
    unblocked = models.BooleanField(default=False)
    unblocked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-blocked_at']

    def __str__(self):
        return f"{self.ip_address} (blocked at {self.blocked_at})"

    def is_active(self):
        if self.unblocked:
            return False
        expiry = self.blocked_at + timedelta(minutes=self.duration_minutes)
        return timezone.now() < expiry

#------------------------------------------------------other models------------------------------------------------------

class RecentActivity(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    activity = models.CharField(max_length=1000)
    module = models.CharField(max_length = 500)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp']),
        ]