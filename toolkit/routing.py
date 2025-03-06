from django.urls import path
from . import consumers

websocket_urlpatterns = [
    path('ws/logs/', consumers.LogConsumer.as_asgi()),
]
