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
    path('network/', views.network_module, name='network_module'),
    path('network/stats/<int:capture_id>/', views.network_stats, name='network_stats'),
    path('network/packets/<int:capture_id>/', views.packet_details, name='packet_details'),
    path('network/add-rule/', views.add_network_rule, name='add_network_rule'),
]

