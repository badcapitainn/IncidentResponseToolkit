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

    # ------------------------------------------------------------------------
    path('network-home/', views.network_home, name='network_home'),
    path('network-home/start/', views.start_network_capture, name='start_network_capture'),
    path('network-home/stop/', views.stop_network_capture, name='stop_network_capture'),
    path('network-traffic/', views.network_traffic_list, name='network_traffic_list'),
    path('network-alerts/', views.network_alerts_list, name='network_alerts_list'),
    path('network-alerts/<int:alert_id>/update/', views.update_alert_status, name='update_alert_status'),
    path('network-rules/', views.network_rules_list, name='network_rules_list'),
    path('network-rules/add/', views.add_network_rule, name='add_network_rule'),
    path('network-rules/<int:rule_id>/toggle/', views.toggle_network_rule, name='toggle_network_rule'),
    path('network-dashboard-data/', views.network_dashboard_data, name='network_dashboard_data'),
]

