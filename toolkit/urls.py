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
]
