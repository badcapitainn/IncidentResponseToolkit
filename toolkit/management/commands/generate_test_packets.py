# config/toolkit/management/commands/generate_test_packets.py
from django.core.management.base import BaseCommand
from modules.network.packet_generator import PacketGenerator
import os
from django.conf import settings


class Command(BaseCommand):
    help = 'Generate test network packets for demonstration'

    def handle(self, *args, **options):
        # Create a test captures directory if it doesn't exist
        test_dir = os.path.join(settings.BASE_DIR, 'test_captures')
        os.makedirs(test_dir, exist_ok=True)

        # Generate a test PCAP file
        pcap_file = os.path.join(test_dir, 'test_capture.pcap')
        PacketGenerator.generate_pcap_file(pcap_file, packet_count=50)

        self.stdout.write(self.style.SUCCESS(
            f'Successfully generated test capture file at {pcap_file}'
        ))