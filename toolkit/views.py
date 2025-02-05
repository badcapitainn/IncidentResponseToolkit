from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from .forms import RegisterForm
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required

from .models import AlertLogs, SuspiciousLogs, WatchlistLogs, ResourceUsageLogs


@csrf_exempt
@login_required(login_url='login')
def dashboard(request):
    alert_logs = AlertLogs.objects.all()
    context = {
        "alert_logs": alert_logs
    }
    template = '../templates/toolkit/dashboard.html'
    return render(request, template, context)


@csrf_exempt
@login_required(login_url='login')
def log_analysis(request):
    alert_logs = AlertLogs.objects.all()
    suspicious_logs = SuspiciousLogs.objects.all()
    watchlist_logs = WatchlistLogs.objects.all()

    context = {
        "alert_logs": alert_logs,
        "suspicious_logs": suspicious_logs,
        "watchlist_logs": watchlist_logs,
    }
    template = '../templates/toolkit/log_analysis.html'

    return render(request, template, context)


@csrf_exempt
@login_required(login_url='login')
def network_analysis(request):
    context = {}
    template = '../templates/toolkit/network_analysis.html'
    return render(request, template, context)


@csrf_exempt
@login_required(login_url='login')
def malware_detection(request):
    context = {}
    template = '../templates/toolkit/malware_detection.html'
    return render(request, template, context)


@csrf_exempt
def user_login(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    else:
        if request.method == 'POST':
            username = request.POST['username']
            password = request.POST['password']
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('dashboard')
            else:
                messages.error(request, 'Invalid username or password.')
        context = {}
        template = '../templates/toolkit/login.html'
        return render(request, template, context)


@csrf_exempt
@login_required(login_url='login')
def registration(request):
    form = RegisterForm()
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Your account has been created!')
            return redirect('dashboard')

    context = {'form': form}
    template = '../templates/toolkit/registration.html'
    return render(request, template, context)


def user_logout(request):
    logout(request)
    return redirect('login')


