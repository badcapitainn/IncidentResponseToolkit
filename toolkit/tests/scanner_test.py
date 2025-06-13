import os
import shutil
from io import StringIO
from unittest import TestCase, mock
from django.test import TestCase as DjangoTestCase
from django.conf import settings
import yara

from toolkit.models import MalwareDetectionResult, Quarantine
from modules.malware_detection.scanner import MalwareScanner  # Replace with your actual module path


class TestMalwareScanner(TestCase):
    def setUp(self):
        self.scanner = MalwareScanner()
        self.test_file = "/path/to/test_file.txt"
        self.test_dir = "/path/to/test_dir"
        self.test_matches = [mock.MagicMock(rule="TestRule")]
        
        # Mock the yara.compile method
        self.yara_patcher = mock.patch('yara.compile')
        self.mock_yara_compile = self.yara_patcher.start()
        self.mock_yara_compile.return_value = mock.MagicMock()

    def tearDown(self):
        self.yara_patcher.stop()

    def test_initialization(self):
        self.assertEqual(self.scanner.rules_path, os.path.join(os.path.dirname(__file__), 'rules'))
        self.assertIsNotNone(self.scanner.rules)

    @mock.patch('os.listdir')
    @mock.patch('os.path.join')
    def test_compile_rules_success(self, mock_join, mock_listdir):
        mock_listdir.return_value = ['rule1.yar', 'rule2.yar']
        mock_join.side_effect = lambda *args: '/'.join(args)
        
        rules = self.scanner._compile_rules()
        self.assertIsNotNone(rules)
        mock_listdir.assert_called_once_with(self.scanner.rules_path)
        self.mock_yara_compile.assert_called_once()

    @mock.patch('os.listdir')
    def test_compile_rules_error(self, mock_listdir):
        mock_listdir.return_value = ['invalid_rule.yar']
        self.mock_yara_compile.side_effect = yara.SyntaxError("Invalid rule")
        
        with self.assertRaises(Exception) as context:
            self.scanner._compile_rules()
        self.assertIn("YARA rule compilation error", str(context.exception))

    @mock.patch('os.path.exists', return_value=True)
    def test_scan_file_success(self, mock_exists):
        self.scanner.rules.match.return_value = self.test_matches
        matches = self.scanner.scan_file(self.test_file)
        self.assertEqual(matches, self.test_matches)
        mock_exists.assert_called_once_with(self.test_file)

    @mock.patch('os.path.exists', return_value=False)
    def test_scan_file_not_found(self, mock_exists):
        with self.assertRaises(FileNotFoundError):
            self.scanner.scan_file(self.test_file)

    @mock.patch('os.path.exists', return_value=True)
    def test_scan_file_error(self, mock_exists):
        self.scanner.rules.match.side_effect = Exception("Scan error")
        with self.assertRaises(Exception) as context:
            self.scanner.scan_file(self.test_file)
        self.assertIn("Scanning error", str(context.exception))

    @mock.patch('os.walk')
    @mock.patch('os.path.exists', return_value=True)
    def test_scan_directory_success(self, mock_exists, mock_walk):
        mock_walk.return_value = [
            (self.test_dir, [], ['file1.txt', 'file2.txt'])
        ]
        
        with mock.patch.object(self.scanner, 'scan_file') as mock_scan:
            mock_scan.return_value = self.test_matches
            results = self.scanner.scan_directory(self.test_dir)
            self.assertEqual(len(results), 2)
            mock_scan.assert_any_call(os.path.join(self.test_dir, 'file1.txt'))
            mock_scan.assert_any_call(os.path.join(self.test_dir, 'file2.txt'))

    @mock.patch('os.path.exists', return_value=False)
    def test_scan_directory_not_found(self, mock_exists):
        with self.assertRaises(FileNotFoundError):
            self.scanner.scan_directory(self.test_dir)

    @mock.patch('os.walk')
    @mock.patch('os.path.exists', return_value=True)
    def test_scan_directory_scan_error(self, mock_exists, mock_walk):
        mock_walk.return_value = [
            (self.test_dir, [], ['file1.txt'])
        ]
        
        with mock.patch.object(self.scanner, 'scan_file', side_effect=Exception("Scan error")):
            with mock.patch('builtins.print') as mock_print:
                results = self.scanner.scan_directory(self.test_dir)
                self.assertEqual(len(results), 0)
                mock_print.assert_called_once()

    @mock.patch('os.path.exists', return_value=True)
    @mock.patch('shutil.move')
    def test_quarantine_file_success(self, mock_move, mock_exists):
        mock_detection = mock.MagicMock()
        mock_detection.pk = 1
        
        with mock.patch('toolkit.models.Quarantine.objects.create') as mock_create:
            result = self.scanner.quarantine_file(self.test_file, mock_detection)
            mock_move.assert_called_once()
            mock_create.assert_called_once()

    @mock.patch('os.path.exists', return_value=False)
    def test_quarantine_file_not_found(self, mock_exists):
        with self.assertRaises(FileNotFoundError):
            self.scanner.quarantine_file(self.test_file, None)

    @mock.patch('os.path.exists', return_value=True)
    @mock.patch('shutil.move', side_effect=Exception("Move failed"))
    def test_quarantine_file_error(self, mock_move, mock_exists):
        with self.assertRaises(Exception):
            self.scanner.quarantine_file(self.test_file, None)

    @mock.patch('os.path.exists', return_value=True)
    def test_quarantine_file_duplicate(self, mock_exists):
        # Mock os.path.exists to return True first, then False
        mock_exists.side_effect = [True, True, False]
        
        with mock.patch('shutil.move') as mock_move:
            with mock.patch('toolkit.models.Quarantine.objects.create') as mock_create:
                self.scanner.quarantine_file(self.test_file, None)
                # Verify the filename was modified for the duplicate
                self.assertIn('_1', mock_move.call_args[0][1])

    @mock.patch.object(MalwareScanner, 'quarantine_file')
    @mock.patch('toolkit.models.MalwareDetectionResult.objects.create')
    @mock.patch('toolkit.models.Alert.objects.create')
    def test_process_matches_success(self, mock_alert_create, mock_detection_create, mock_quarantine):
        # Setup mocks
        mock_detection = mock.MagicMock()
        mock_detection_create.return_value = mock_detection
        mock_quarantine.return_value = mock.MagicMock(quarantine_path="/quarantine/path")
        
        result = self.scanner._process_matches(self.test_file, self.test_matches)
        
        self.assertIsNotNone(result)
        mock_detection_create.assert_called_once()
        mock_quarantine.assert_called_once_with(self.test_file, mock_detection)
        mock_alert_create.assert_called_once()

    @mock.patch('toolkit.models.MalwareDetectionResult.objects.create')
    def test_process_matches_no_matches(self, mock_detection_create):
        result = self.scanner._process_matches(self.test_file, [])
        self.assertIsNone(result)
        mock_detection_create.assert_not_called()

    @mock.patch.object(MalwareScanner, 'quarantine_file', side_effect=Exception("Quarantine failed"))
    @mock.patch('toolkit.models.MalwareDetectionResult.objects.create')
    @mock.patch('builtins.print')
    def test_process_matches_quarantine_failure(self, mock_print, mock_detection_create, mock_quarantine):
        with self.assertRaises(Exception):
            self.scanner._process_matches(self.test_file, self.test_matches)
        mock_print.assert_called_once()


class TestMalwareScannerDjango(DjangoTestCase):
    def setUp(self):
        self.scanner = MalwareScanner()
        self.test_file = "/path/to/test_file.txt"
        
        # Mock the yara rules matching
        self.scanner.rules = mock.MagicMock()
        self.scanner.rules.match.return_value = [mock.MagicMock(rule="TestRule")]

    @mock.patch('os.path.exists', return_value=True)
    @mock.patch('shutil.move')
    def test_quarantine_file_db_integration(self, mock_move, mock_exists):
        detection_result = MalwareDetectionResult.objects.create(
            file_path=self.test_file,
            is_malicious=True,
            malware_type="TestRule"
        )
        
        quarantine = self.scanner.quarantine_file(self.test_file, detection_result)
        
        self.assertEqual(Quarantine.objects.count(), 1)
        self.assertEqual(quarantine.original_path, self.test_file)
        self.assertEqual(quarantine.detection_result, detection_result)

    @mock.patch('os.path.exists', return_value=True)
    @mock.patch('shutil.move')
    def test_process_matches_db_integration(self, mock_move, mock_exists):
        result = self.scanner._process_matches(self.test_file, self.scanner.rules.match())
        
        self.assertEqual(MalwareDetectionResult.objects.count(), 1)
        self.assertEqual(Quarantine.objects.count(), 1)
        self.assertEqual(Alert.objects.count(), 1)
        
        detection = MalwareDetectionResult.objects.first()
        self.assertTrue(detection.is_malicious)
        self.assertEqual(detection.malware_type, "TestRule")
        
        alert = Alert.objects.first()
        self.assertEqual(alert.module, "MALWARE")
        self.assertEqual(alert.severity, "HIGH")