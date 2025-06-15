# modules/reports.py
from datetime import datetime, timedelta
from django.db.models import Count, Q
from django.utils import timezone
from toolkit.models import (
    MalwareDetectionResult, NetworkAlert, LogAlert, BlockedIP,
    LogEntry, NetworkCapture, RecentActivity, Report
)

class ReportGenerator:
    def __init__(self, report_type, user, start_date=None, end_date=None):
        self.report_type = report_type
        self.user = user
        self.start_date = start_date or (timezone.now() - timedelta(days=7))
        self.end_date = end_date or timezone.now()
        self.data = {}
    
    def datetime_to_str(self, dt):
        """Convert datetime to ISO format string if it's a datetime object"""
        if isinstance(dt, datetime):
            return dt.isoformat()
        return dt
    
    def process_queryset(self, queryset):
        """Convert datetime fields in queryset values to strings"""
        result = list(queryset)
        for item in result:
            for key, value in item.items():
                item[key] = self.datetime_to_str(value)
        return result
    
    def generate_threat_summary(self):
        # Malware data
        malware_results = MalwareDetectionResult.objects.filter(
            scan_time__gte=self.start_date,
            scan_time__lte=self.end_date
        )
        
        self.data['malware'] = {
            'total_scans': malware_results.count(),
            'malicious_count': malware_results.filter(is_malicious=True).count(),
            'by_type': self.process_queryset(
                malware_results.filter(is_malicious=True)
                .values('malware_type')
                .annotate(count=Count('malware_type'))
                .order_by('-count')
            ),
            'scan_types': self.process_queryset(
                malware_results.values('scan_type')
                .annotate(count=Count('scan_type'))
                .order_by('-count')
            )
        }
        
        # Network alerts
        network_alerts = NetworkAlert.objects.filter(
            timestamp__gte=self.start_date,
            timestamp__lte=self.end_date
        )
        
        self.data['network'] = {
            'total_alerts': network_alerts.count(),
            'by_severity': self.process_queryset(
                network_alerts.values('severity')
                .annotate(count=Count('severity'))
                .order_by('-count')
            ),
            'by_protocol': self.process_queryset(
                network_alerts.exclude(protocol__isnull=True)
                .values('protocol')
                .annotate(count=Count('protocol'))
                .order_by('-count')
            ),
            'top_src_ips': self.process_queryset(
                network_alerts.exclude(src_ip__isnull=True)
                .values('src_ip')
                .annotate(count=Count('src_ip'))
                .order_by('-count')[:5]
            ),
            'top_dst_ips': self.process_queryset(
                network_alerts.exclude(dst_ip__isnull=True)
                .values('dst_ip')
                .annotate(count=Count('dst_ip'))
                .order_by('-count')[:5]
            )
        }
        
        # Log alerts
        log_alerts = LogAlert.objects.filter(
            timestamp__gte=self.start_date,
            timestamp__lte=self.end_date
        )
        
        self.data['logs'] = {
            'total_alerts': log_alerts.count(),
            'by_level': self.process_queryset(
                log_alerts.values('level')
                .annotate(count=Count('level'))
                .order_by('-count')
            ),
            'resolved_rate': {
                'resolved': log_alerts.filter(resolved=True).count(),
                'unresolved': log_alerts.filter(resolved=False).count()
            }
        }
        
        # Blocked IPs
        blocked_ips = BlockedIP.objects.filter(
            blocked_at__gte=self.start_date,
            blocked_at__lte=self.end_date
        )
        
        self.data['blocked'] = {
            'total_blocked': blocked_ips.count(),
            'still_blocked': blocked_ips.filter(unblocked=False).count(),
            'top_reasons': self.process_queryset(
                blocked_ips.values('reason')
                .annotate(count=Count('reason'))
                .order_by('-count')[:3]
            )
        }
        
        # Recent activity
        activities = RecentActivity.objects.filter(
            timestamp__gte=self.start_date,
            timestamp__lte=self.end_date
        ).order_by('-timestamp')[:10]
        
        self.data['activities'] = self.process_queryset(
            activities.values('timestamp', 'activity', 'module')
        )
        
        return self.data
    
    # Update other generate_* methods similarly with process_queryset
    def generate_threat_intelligence(self):
        # Malware intelligence
        malware_results = MalwareDetectionResult.objects.filter(
            is_malicious=True,
            scan_time__gte=self.start_date,
            scan_time__lte=self.end_date
        ).order_by('-scan_time')
        
        self.data['malware_intel'] = {
            'recent_malware': self.process_queryset(
                malware_results.values('file_path', 'malware_type', 'scan_time', 'details')[:10]
            ),
            'emerging_threats': self.process_queryset(
                malware_results.values('malware_type')
                .annotate(count=Count('malware_type'))
                .order_by('-count')[:5]
            )
        }
        
        # Network intelligence
        network_alerts = NetworkAlert.objects.filter(
            timestamp__gte=self.start_date,
            timestamp__lte=self.end_date,
            severity__in=['high', 'critical']
        ).order_by('-timestamp')
        
        self.data['network_intel'] = {
            'critical_alerts': self.process_queryset(
                network_alerts.values('timestamp', 'rule_name', 'src_ip', 'dst_ip', 'protocol', 'details')[:10]
            ),
            'common_attack_patterns': self.process_queryset(
                network_alerts.values('rule_name')
                .annotate(count=Count('rule_name'))
                .order_by('-count')[:5]
            )
        }
        
        # Threat correlation
        threat_correlation = []
        malware_files = malware_results.values_list('file_path', flat=True)
        
        for alert in network_alerts:
            if any(file in alert.details.get('payload', '') for file in malware_files):
                threat_correlation.append({
                    'timestamp': self.datetime_to_str(alert.timestamp),
                    'alert_id': alert.id,
                    'malware_file': next((f for f in malware_files if f in alert.details.get('payload', '')), None),
                    'details': alert.details
                })
        
        self.data['threat_correlation'] = threat_correlation[:10]
        
        return self.data
    
    def generate_system_safety(self):
        # System health metrics
        log_entries = LogEntry.objects.filter(
            timestamp__gte=self.start_date,
            timestamp__lte=self.end_date
        )
        
        self.data['system_health'] = {
            'log_volume': log_entries.count(),
            'error_rate': log_entries.filter(level__in=['ERROR', 'CRITICAL']).count(),
            'compression_rate': log_entries.filter(compressed=True).count(),
            'log_levels': self.process_queryset(
                log_entries.values('level')
                .annotate(count=Count('level'))
                .order_by('-count')
            )
        }
        
        # Network health
        network_captures = NetworkCapture.objects.filter(
            start_time__gte=self.start_date,
            start_time__lte=self.end_date
        )
        
        self.data['network_health'] = {
            'capture_sessions': network_captures.count(),
            'average_packets': network_captures.aggregate(avg=Avg('packet_count'))['avg'] or 0,
            'active_captures': network_captures.filter(is_active=True).count()
        }
        
        # Protection status
        malware_results = MalwareDetectionResult.objects.filter(
            scan_time__gte=self.start_date,
            scan_time__lte=self.end_date
        )
        
        self.data['protection_status'] = {
            'malware_detection_rate': malware_results.filter(is_malicious=True).count(),
            'quarantine_success': Quarantine.objects.filter(
                quarantine_time__gte=self.start_date,
                quarantine_time__lte=self.end_date,
                restored=False
            ).count(),
            'blocked_threats': BlockedIP.objects.filter(
                blocked_at__gte=self.start_date,
                blocked_at__lte=self.end_date
            ).count()
        }
        
        # Recommendations
        recommendations = []
        
        # Check for high error logs
        if self.data['system_health']['error_rate'] > 50:
            recommendations.append({
                'category': 'System Errors',
                'message': 'High number of error logs detected. Investigate system stability.',
                'severity': 'high'
            })
        
        # Check for unresolved critical alerts
        critical_alerts = NetworkAlert.objects.filter(
            severity='critical',
            status='open',
            timestamp__gte=self.start_date,
            timestamp__lte=self.end_date
        ).count()
        
        if critical_alerts > 0:
            recommendations.append({
                'category': 'Unresolved Alerts',
                'message': f'{critical_alerts} critical alerts remain unresolved.',
                'severity': 'critical'
            })
        
        self.data['recommendations'] = recommendations
        
        return self.data
    
    def generate_report(self):
        report = Report.objects.create(
            report_type=self.report_type,
            title=f"{self.get_report_type_display()} - {datetime.now().strftime('%Y-%m-%d')}",
            generated_by=self.user,
            start_date=self.start_date,
            end_date=self.end_date
        )
        
        if self.report_type == 'THREAT_SUMMARY':
            report_data = self.generate_threat_summary()
        elif self.report_type == 'THREAT_INTEL':
            report_data = self.generate_threat_intelligence()
        elif self.report_type == 'SYSTEM_SAFETY':
            report_data = self.generate_system_safety()
        
        report.data = report_data
        report.save()
        
        return report
    
    def get_report_type_display(self):
        return dict(Report.REPORT_TYPES)[self.report_type]