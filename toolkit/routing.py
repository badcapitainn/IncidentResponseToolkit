from django.urls import path, re_path
from . import consumers

websocket_urlpatterns = [
    path('ws/logs/', consumers.LogConsumer.as_asgi()),
    re_path(r'ws/resources/$', consumers.ResourceConsumer.as_asgi()),
    re_path(r'ws/network/$', consumers.NetworkAnalysisConsumer.as_asgi()),
]
