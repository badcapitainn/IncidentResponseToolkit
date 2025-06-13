import os
import gzip
from io import StringIO, BytesIO
from datetime import datetime, timedelta
from unittest import TestCase, mock
from django.test import TestCase as DjangoTestCase
from django.conf import settings
from collections import defaultdict
from loguru import logger
from toolkit.models import LogEntry, LogSource, LogAlert
from modules.firewall.blocker import FirewallBlocker

from modules.log_module.core import LogAnalyzer  # Replace with your actual module path

import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()
import dpkt



class TestLogAnalyzer(TestCase):
    def setUp(self):
        self.analyzer = LogAnalyzer()
        self.analyzer.logger = logger  # Use the actual logger for testing
        self.test_log_line = "[2023-01-01 12:00:00] [ERROR] Test error message"
        self.test_log_line_with_ip = "[2023-01-01 12:00:00] [ERROR] Attack from 192.168.1.1"

    def test_initialization(self):
        self.assertEqual(self.analyzer.retention_days, 30)
        self.assertTrue(self.analyzer.compression_enabled)
        self.assertEqual(self.analyzer.alert_thresholds['ERROR'], 5)
        self.assertEqual(self.analyzer.current_alerts, [])

    def test_configure_logger(self):
        with mock.patch('loguru.logger.add') as mock_add:
            self.analyzer.configure_logger()
            mock_add.assert_called_once()
            args, kwargs = mock_add.call_args
            self.assertIn("log_analysis_{time}.log", args[0])
            self.assertEqual(kwargs['rotation'], "10 MB")
            self.assertEqual(kwargs['retention'], "30 days")
            self.assertEqual(kwargs['compression'], "zip")
            self.assertEqual(kwargs['level'], "INFO")

    @mock.patch('gzip.open')
    @mock.patch('builtins.open', new_callable=mock.mock_open)
    def test_process_log_file_regular(self, mock_open, mock_gzip_open):
        mock_file = StringIO(self.test_log_line + "\n" + self.test_log_line_with_ip + "\n")
        mock_open.return_value = mock_file
        
        with mock.patch.object(self.analyzer, 'process_log_line') as mock_process:
            result = self.analyzer.process_log_file("/path/to/logfile.log")
            self.assertTrue(result)
            self.assertEqual(mock_process.call_count, 2)

    @mock.patch('gzip.open')
    def test_process_log_file_gzipped(self, mock_gzip_open):
        mock_file = StringIO(self.test_log_line + "\n" + self.test_log_line_with_ip + "\n")
        mock_gzip_open.return_value = mock_file
        
        with mock.patch.object(self.analyzer, 'process_log_line') as mock_process:
            result = self.analyzer.process_log_file("/path/to/logfile.gz")
            self.assertTrue(result)
            mock_gzip_open.assert_called_once_with("/path/to/logfile.gz", 'rt')
            self.assertEqual(mock_process.call_count, 2)

    @mock.patch('gzip.open')
    @mock.patch('builtins.open')
    def test_process_log_file_error(self, mock_open, mock_gzip_open):
        mock_open.side_effect = IOError("File not found")
        
        with mock.patch.object(self.analyzer.logger, 'error') as mock_error:
            result = self.analyzer.process_log_file("/path/to/nonexistent.log")
            self.assertFalse(result)
            mock_error.assert_called_once()

    def test_process_log_line_standard_format(self):
        with mock.patch('toolkit.models.LogEntry.objects.create') as mock_create:
            result = self.analyzer.process_log_line(self.test_log_line, "system")
            self.assertIsNotNone(result)
            mock_create.assert_called_once()

    def test_process_log_line_with_ip(self):
        with mock.patch('toolkit.models.LogEntry.objects.create'):
            result = self.analyzer.process_log_line(self.test_log_line_with_ip, "system")
            self.assertEqual(len(self.analyzer.current_alerts), 1)
            self.assertEqual(self.analyzer.current_alerts[0]['ip'], '192.168.1.1')

    def test_process_log_line_non_standard_format(self):
        with mock.patch('toolkit.models.LogEntry.objects.create') as mock_create:
            result = self.analyzer.process_log_line("This is a raw log message", "system")
            self.assertIsNotNone(result)
            mock_create.assert_called_once()

    def test_process_log_line_error(self):
        with mock.patch('toolkit.models.LogEntry.objects.create', side_effect=Exception("DB error")):
            with mock.patch.object(self.analyzer.logger, 'error') as mock_error:
                result = self.analyzer.process_log_line(self.test_log_line, "system")
                self.assertIsNone(result)
                mock_error.assert_called_once()

    @mock.patch('toolkit.models.LogAlert.objects.create')
    @mock.patch.object(FirewallBlocker, 'block_ip')
    def test_check_for_alerts_thresholds(self, mock_block_ip, mock_alert_create):
        # Add enough ERROR logs to trigger threshold
        for _ in range(6):
            self.analyzer.current_alerts.append({
                'timestamp': datetime.now(),
                'level': 'ERROR',
                'message': 'Test error',
                'source': 'system'
            })
        
        self.analyzer.check_for_alerts()
        mock_alert_create.assert_called_once()
        self.assertEqual(len(self.analyzer.current_alerts), 0)

    @mock.patch('toolkit.models.LogAlert.objects.create')
    @mock.patch.object(FirewallBlocker, 'block_ip', return_value=True)
    def test_check_for_alerts_ip_blocking(self, mock_block_ip, mock_alert_create):
        # Add enough CRITICAL logs from same IP to trigger blocking
        for _ in range(3):
            self.analyzer.current_alerts.append({
                'timestamp': datetime.now(),
                'level': 'CRITICAL',
                'message': 'Attack detected',
                'source': 'system',
                'ip': '192.168.1.100'
            })
        
        self.analyzer.check_for_alerts()
        mock_block_ip.assert_called_once_with(
            ip_address='192.168.1.100',
            reason="Excessive malicious events (defaultdict(<class 'int'>, {'CRITICAL': 3}))",
            duration_minutes=120
        )
        self.assertEqual(mock_alert_create.call_count, 2)  # One for threshold, one for block

    @mock.patch('toolkit.models.LogAlert.objects.create')
    @mock.patch.object(FirewallBlocker, 'block_ip', side_effect=Exception("Block failed"))
    def test_check_for_alerts_ip_block_failure(self, mock_block_ip, mock_alert_create):
        # Add enough CRITICAL logs from same IP to trigger blocking
        for _ in range(3):
            self.analyzer.current_alerts.append({
                'timestamp': datetime.now(),
                'level': 'CRITICAL',
                'message': 'Attack detected',
                'source': 'system',
                'ip': '192.168.1.100'
            })
        
        with mock.patch.object(self.analyzer.logger, 'error') as mock_error:
            self.analyzer.check_for_alerts()
            mock_error.assert_called_once()
            self.assertEqual(mock_alert_create.call_count, 2)  # One for threshold, one for block failure

    @mock.patch('toolkit.models.LogAlert.objects.create')
    def test_create_alert(self, mock_create):
        self.analyzer.create_alert('ERROR', 'Test alert', 'Details')
        mock_create.assert_called_once_with(
            level='ERROR',
            message='Test alert',
            details='Details',
            timestamp=mock.ANY  # We can't mock datetime.now() easily
        )

    @mock.patch('toolkit.models.LogEntry.objects.filter')
    def test_compress_old_logs(self, mock_filter):
        mock_queryset = mock.MagicMock()
        mock_filter.return_value = mock_queryset
        mock_log = mock.MagicMock()
        mock_queryset.__iter__.return_value = [mock_log]
        
        self.analyzer.compress_old_logs()
        mock_filter.assert_called_once_with(timestamp__lt=mock.ANY, compressed=False)
        self.assertTrue(mock_log.compressed)
        mock_log.save.assert_called_once()

    @mock.patch('toolkit.models.LogEntry.objects.count')
    @mock.patch('toolkit.models.LogEntry.objects.filter')
    @mock.patch('toolkit.models.LogSource.objects.all')
    @mock.patch('toolkit.models.LogAlert.objects.filter')
    def test_get_log_statistics(self, mock_alert_filter, mock_source_all, 
                              mock_entry_filter, mock_entry_count):
        # Setup mocks
        mock_entry_count.return_value = 100
        
        # Mock level counts
        level_mock = mock.MagicMock()
        level_mock.count.side_effect = [10, 20, 30, 40]  # For each level
        mock_entry_filter.return_value = level_mock
        
        # Mock sources
        source_mock = mock.MagicMock()
        source_mock.name = "test_source"
        mock_source_all.return_value = [source_mock]
        
        # Mock source counts
        source_count_mock = mock.MagicMock()
        source_count_mock.count.return_value = 50
        mock_entry_filter.return_value = source_count_mock
        
        # Mock alerts
        alert_mock = mock.MagicMock()
        alert_mock.count.return_value = 5
        mock_alert_filter.return_value = alert_mock
        
        stats = self.analyzer.get_log_statistics()
        
        self.assertEqual(stats['total_logs'], 100)
        self.assertEqual(stats['levels']['ERROR'], 10)  # Assuming first level is ERROR
        self.assertEqual(stats['sources']['test_source'], 50)
        self.assertEqual(stats['recent_alerts'], 5)


class TestLogAnalyzerDjango(DjangoTestCase):
    def setUp(self):
        self.analyzer = LogAnalyzer()
        self.source = LogSource.objects.create(name="test_source")
        
    def test_process_log_line_db_integration(self):
        line = "[2023-01-01 12:00:00] [ERROR] Test error message"
        result = self.analyzer.process_log_line(line, "test_source")
        
        self.assertIsNotNone(result)
        self.assertEqual(LogEntry.objects.count(), 1)
        entry = LogEntry.objects.first()
        self.assertEqual(entry.level, "ERROR")
        self.assertEqual(entry.message, "Test error message")
        self.assertEqual(entry.source.name, "test_source")

    def test_create_alert_db_integration(self):
        self.analyzer.create_alert('ERROR', 'Test alert', 'Details')
        
        self.assertEqual(LogAlert.objects.count(), 1)
        alert = LogAlert.objects.first()
        self.assertEqual(alert.level, "ERROR")
        self.assertEqual(alert.message, "Test alert")
        self.assertEqual(alert.details, "Details")
        self.assertFalse(alert.resolved)