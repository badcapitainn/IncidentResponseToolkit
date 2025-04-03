import json
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from .forms import RegisterForm
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from .models import AlertLogs, SuspiciousLogs, WatchlistLogs, ResourceUsageLogs, MaliciousPackets, SuspiciousPackets, \
    SystemMetrics


@csrf_exempt
@login_required(login_url='login')
def dashboard(request):
    watch_list_logs = WatchlistLogs.objects.all()
    alert_logs = AlertLogs.objects.all()

    # Get the latest application-specific resource usage data
    resource_data = SystemMetrics.objects.filter(is_application_only=True) \
                        .order_by('-timestamp')[:30]  # Last 30 readings

    # Prepare data for the template
    timestamps = [data.timestamp.strftime('%H:%M:%S') for data in resource_data]
    cpu_data = [data.cpu_usage for data in resource_data]
    ram_data = [data.ram_used for data in resource_data]

    # For disk, we'll use read/write operations instead of percentage
    disk_read_data = [data.disk_read for data in resource_data]
    disk_write_data = [data.disk_write for data in resource_data]

    context = {
        "alert_logs": alert_logs,
        "watch_list_logs": watch_list_logs,
        "timestamps": json.dumps(timestamps[::-1]),  # Reverse to show oldest first
        "cpu_data": json.dumps(cpu_data[::-1]),
        "ram_data": json.dumps(ram_data[::-1]),
        "disk_read_data": json.dumps(disk_read_data[::-1]),
        "disk_write_data": json.dumps(disk_write_data[::-1]),
        "latest_ram": resource_data[0].ram_used if resource_data else 0,
        "latest_disk_read": resource_data[0].disk_read if resource_data else 0,
        "latest_disk_write": resource_data[0].disk_write if resource_data else 0,
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

    # Send WebSocket message
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        "logs",
        {
            'type': 'log_message',
            'message': 'Logs updated'
        }
    )

    return render(request, template, context)


@csrf_exempt
@login_required(login_url='login')
def network_analysis(request):
    suspicious_packets = SuspiciousPackets.objects.all().order_by('-timeStamp')
    malicious_packets = MaliciousPackets.objects.all().order_by('-timeStamp')

    context = {
        "suspicious_packets": suspicious_packets,
        "malicious_packets": malicious_packets,
    }
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
