from django.http import HttpResponseForbidden
from modules.firewall.blocker import FirewallBlocker

class BlockedIPMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.blocker = FirewallBlocker()

    def __call__(self, request):
        client_ip = self.get_client_ip(request)
        
        if client_ip and self.blocker.is_blocked(client_ip):
            return HttpResponseForbidden(
                "Your IP address has been blocked due to suspicious activity"
            )
        
        return self.get_response(request)

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip