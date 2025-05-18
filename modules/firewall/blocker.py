import ipaddress
from django.conf import settings
from toolkit.models import BlockedIP
from loguru import logger
from django.utils import timezone

class FirewallBlocker:
    def __init__(self):
        self.blocked_ips = set()
        self.logger = logger
        self.logger.info("Initializing Application-Level FirewallBlocker")
        self.load_existing_blocks()

    def load_existing_blocks(self):
        """Load previously blocked IPs from database"""
        try:
            for entry in BlockedIP.objects.filter(unblocked=False):
                self.blocked_ips.add(entry.ip_address)
            self.logger.info(f"Loaded {len(self.blocked_ips)} active blocked IPs")
        except Exception as e:
            self.logger.error(f"Error loading blocked IPs: {str(e)}")

    def is_blocked(self, ip_address):
        """Check if IP is blocked in our database"""
        try:
            return ip_address in self.blocked_ips
        except Exception as e:
            self.logger.error(f"Error checking blocked status for {ip_address}: {str(e)}")
            return False

    def block_ip(self, ip_address, reason="", duration_minutes=60):
        """Block an IP address at application level"""
        try:
            # Validate IP address
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private:
                self.logger.warning(f"Blocking private IP: {ip_address}")

            if self.is_blocked(ip_address):
                self.logger.warning(f"IP {ip_address} is already blocked")
                return False

            self.logger.info(f"Creating application-level block for IP {ip_address}")

            # Record in database
            BlockedIP.objects.create(
                ip_address=ip_address,
                reason=reason,
                duration_minutes=duration_minutes
            )
            self.blocked_ips.add(ip_address)
            self.logger.success(f"Successfully recorded block for IP {ip_address}")
            return True

        except ValueError as e:
            self.logger.error(f"Invalid IP address {ip_address}: {str(e)}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error blocking IP {ip_address}: {str(e)}")
            return False

    def unblock_ip(self, ip_address):
        """Unblock an IP address"""
        try:
            ipaddress.ip_address(ip_address)  # Validate IP
            
            if not self.is_blocked(ip_address):
                self.logger.warning(f"IP {ip_address} was not blocked")
                return False

            # Update database
            BlockedIP.objects.filter(ip_address=ip_address).update(
                unblocked=True,
                unblocked_at=timezone.now()
            )
            self.blocked_ips.discard(ip_address)
            self.logger.success(f"Successfully unblocked IP {ip_address}")
            return True

        except Exception as e:
            self.logger.error(f"Error unblocking IP {ip_address}: {str(e)}")
            return False