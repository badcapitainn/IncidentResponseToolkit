import time

from django.core.management.base import BaseCommand
from modules.log_module.utils import RealTimeLogMonitor
from django.conf import settings


class Command(BaseCommand):
    help = 'Starts real-time log monitoring service'

    def handle(self, *args, **options):
        monitor = RealTimeLogMonitor()

        self.stdout.write(self.style.SUCCESS('Starting log monitor...'))
        try:
            monitor.start()
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stdout.write(self.style.SUCCESS('\nStopping log monitor...'))
            monitor.stop()