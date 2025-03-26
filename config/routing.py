from channels.routing import ProtocolTypeRouter, URLRouter
from django.core.asgi import get_asgi_application
import toolkit.routing
from channels.auth import AuthMiddlewareStack

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": AuthMiddlewareStack(
        URLRouter(
            toolkit.routing.websocket_urlpatterns
        )
    ),
})