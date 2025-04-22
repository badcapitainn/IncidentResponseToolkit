import json
import os
from datetime import datetime

from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from .forms import RegisterForm
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from .models import AlertLogs, SuspiciousLogs, WatchlistLogs, MaliciousPackets, SuspiciousPackets, SystemMetrics, \
    MalwareDetectionResult
from modules.malware_detection.scanner import MalwareScanner
from django.conf import settings
from django.core.files.storage import FileSystemStorage


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
    if request.method == 'POST':
        # Handle file upload
        if 'file_scan' in request.FILES:
            return handle_file_scan(request)
        # Handle directory scan
        elif 'directory_path' in request.POST:
            return handle_directory_scan(request)

    # Get recent scan results
    recent_scans = MalwareDetectionResult.objects.all().order_by('-scan_time')[:10]
    return render(request, 'toolkit/malware_detection.html', {
        'recent_scans': recent_scans
    })


def handle_file_scan(request):
    uploaded_file = request.FILES['file_scan']
    fs = FileSystemStorage()

    # Save the uploaded file temporarily
    filename = fs.save(uploaded_file.name, uploaded_file)
    file_path = os.path.join(settings.MEDIA_ROOT, filename)

    # Scan the file
    scanner = MalwareScanner()
    try:
        matches = scanner.scan_file(file_path)

        if matches:
            result = MalwareDetectionResult.objects.create(
                file_path=file_path,
                scan_time=datetime.now(),
                is_malicious=True,
                malware_type=", ".join([m.rule for m in matches]),
                details=str(matches),
                detected_by=request.user
            )
            messages.warning(request, f"Malware detected: {result.malware_type}")
        else:
            result = MalwareDetectionResult.objects.create(
                file_path=file_path,
                scan_time=datetime.now(),
                is_malicious=False,
                detected_by=request.user
            )
            messages.success(request, "No malware detected in the file.")

    except Exception as e:
        messages.error(request, f"Scanning error: {str(e)}")
    finally:
        # Clean up the temporary file
        if os.path.exists(file_path):
            os.remove(file_path)

    return redirect('malware_detection')


def handle_directory_scan(request):
    directory_path = request.POST['directory_path']

    if not os.path.isdir(directory_path):
        messages.error(request, "Invalid directory path.")
        return redirect('malware_detection')

    scanner = MalwareScanner()
    try:
        results = scanner.scan_directory(directory_path)

        if results:
            messages.warning(request, f"Found {len(results)} malicious files in the directory.")
        else:
            messages.success(request, "No malware detected in the directory.")

    except Exception as e:
        messages.error(request, f"Scanning error: {str(e)}")

    return redirect('malware_detection')


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
