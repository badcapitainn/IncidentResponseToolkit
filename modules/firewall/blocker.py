import subprocess
import ipaddress
from django.conf import settings
from toolkit.models import BlockedIP


class FirewallBlocker:
    def __init__(self):
        self.blocked_ips = set()
        self.load_existing_blocks()

    def load_existing_blocks(self):
        """Load previously blocked IPs from database"""
        for entry in BlockedIP.objects.all():
            self.blocked_ips.add(entry.ip_address)

    def block_ip(self, ip_address, reason="", duration_minutes=60):
        """Block an IP address at the firewall level"""
        try:
            # Validate IP address
            ipaddress.ip_address(ip_address)

            if ip_address in self.blocked_ips:
                return False  # Already blocked

            # Linux iptables example (adjust for Windows if needed)
            subprocess.run([
                'sudo', 'iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'
            ], check=True)

            # Windows alternative (using PowerShell)
            subprocess.run([
                'powershell', '-Command',
                f'New-NetFirewallRule -DisplayName "Block {ip_address}" -Direction Inbound -RemoteAddress {ip_address} -Action Block'
            ], check=True)

            # Record in database
            BlockedIP.objects.create(
                ip_address=ip_address,
                reason=reason,
                duration_minutes=duration_minutes
            )
            self.blocked_ips.add(ip_address)
            return True

        except (ValueError, subprocess.CalledProcessError) as e:
            print(f"Failed to block IP {ip_address}: {str(e)}")
            return False

    def unblock_ip(self, ip_address):
        """Unblock an IP address"""
        try:
            # Linux iptables example
            subprocess.run([
                'sudo', 'iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP'
            ], check=True)

            # Windows alternative
            subprocess.run([
                'powershell', '-Command',
                f'Remove-NetFirewallRule -DisplayName "Block {ip_address}"'
            ], check=True)

            # Update database
            BlockedIP.objects.filter(ip_address=ip_address).delete()
            self.blocked_ips.discard(ip_address)
            return True

        except (ValueError, subprocess.CalledProcessError) as e:
            print(f"Failed to unblock IP {ip_address}: {str(e)}")
            return False