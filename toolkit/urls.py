from django.urls import path, include
from toolkit import views


urlpatterns = [
    path("home/", views.dashboard, name="dashboard"),
    path("login/", views.user_login, name="login"),
    path("home/registration/", views.registration, name="registration"),
    path("logout/", views.user_logout, name="logout"),
    path("home/log_analysis/", views.log_analysis, name="log_analysis"),
    path("home/network_analysis/", views.network_analysis, name="network_analysis"),
    path('malware-detection/', views.malware_detection, name='malware_detection'),
    path('malware-detection/delete/', views.delete_file, name='delete_quarantined'),
    path('malware-detection/restore/', views.restore_file, name='restore_quarantined'),
    path('network/', views.network_module, name='network_module'),
    path('network/stats/<int:capture_id>/', views.network_stats, name='network_stats'),
    path('network/packets/<int:capture_id>/', views.packet_details, name='packet_details'),
    path('network/add-rule/', views.add_network_rule, name='add_network_rule'),

    path('logs/', views.log_module, name='log_module'),
    path('logs/details/', views.log_details, name='log_details'),
    path('logs/alerts/', views.log_alerts, name='log_alerts'),
    path('logs/alerts/<int:alert_id>/resolve/', views.resolve_alert, name='resolve_alert'),
    path('logs/upload/', views.upload_log_file, name='upload_log_file'),
    path('logs/stats/', views.log_stats_api, name='log_stats_api'),
    path('logs/monitor/start/', views.start_monitoring, name='start_monitoring'),
    path('logs/monitor/stop/', views.stop_monitoring, name='stop_monitoring'),
    path('logs/monitor/status/', views.monitoring_status, name='monitoring_status'),
    path('blocked-ips/', views.blocked_ips, name='blocked_ips'),
]

