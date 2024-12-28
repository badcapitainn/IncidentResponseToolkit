from django.urls import path, include

from toolkit import views

urlpatterns = [
    path("home/", views.dashboard, name="dashboard"),
    path("login/", views.user_login, name="login"),
    path("registration/", views.registration, name="registration"),
    path("logout/", views.user_logout, name="logout"),
]
