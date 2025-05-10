import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from .core import LogAnalyzer
import threading
from django.conf import settings


class RealTimeLogMonitor:
    def __init__(self, watch_dirs=None):
        self.watch_dirs = watch_dirs or [settings.LOGS_DIR]
        self.analyzer = LogAnalyzer()
        self.observer = Observer()
        self.running = False
        self.thread = None

    def start(self):
        """Start monitoring in a background thread"""
        if self.running:
            return

        self.running = True
        self.thread = threading.Thread(target=self._run_monitor, daemon=True)
        self.thread.start()

    def stop(self):
        """Stop monitoring"""
        self.running = False
        if self.observer.is_alive():
            self.observer.stop()
            self.observer.join()
        if self.thread:
            self.thread.join()

    def _run_monitor(self):
        """Internal method to run the monitor"""
        event_handler = LogFileHandler(self.analyzer)

        for directory in self.watch_dirs:
            self.observer.schedule(event_handler, directory, recursive=True)

        self.observer.start()

        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
        finally:
            self.observer.stop()
            self.observer.join()


class LogFileHandler(FileSystemEventHandler):
    def __init__(self, log_analyzer, patterns=None):
        super().__init__()
        self.analyzer = log_analyzer
        self.patterns = patterns or ["*.log", "*.log.gz"]
        self.file_positions = {}  # Track last read position in each file

    def on_modified(self, event):
        if not event.is_directory:
            for pattern in self.patterns:
                if event.src_path.endswith(pattern):
                    self.process_file(event.src_path)
                    break

    def process_file(self, file_path):
        """Process new content in a log file"""
        current_position = self.file_positions.get(file_path, 0)

        try:
            with open(file_path, 'r') as f:
                # Seek to last read position
                f.seek(current_position)

                # Read new lines
                new_lines = f.readlines()

                # Update position
                self.file_positions[file_path] = f.tell()

                # Process each new line
                for line in new_lines:
                    self.analyzer.process_log_line(line.strip(), os.path.basename(file_path))

        except (IOError, PermissionError) as e:
            print(f"Error reading file {file_path}: {str(e)}")


class LogMonitor:
    def __init__(self, watch_dir, log_analyzer):
        self.watch_dir = watch_dir
        self.log_analyzer = log_analyzer
        self.observer = Observer()

    def start(self):
        event_handler = LogFileHandler(self.log_analyzer)
        self.observer.schedule(event_handler, self.watch_dir, recursive=True)
        self.observer.start()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.observer.stop()

        self.observer.join()
