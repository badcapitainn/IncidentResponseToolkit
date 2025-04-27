import json
import os

from django.core.paginator import Paginator
from django.db import models
from django.db.models import Count
from django.utils import timezone
from datetime import datetime, timedelta
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

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
# -------------------------------network test imports --------------------------------------------
from toolkit.models import NetworkTraffic, NetworkAlert, NetworkRule
from modules.network.analyzer import NetworkAnalyzer
from modules.network.utils import get_network_interfaces, get_network_stats


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


# -------------------------------- network test views -----------------------------------------------------------

@csrf_exempt
@login_required(login_url='login')
def network_home(request):
    # Get current analyzer instance or create new one
    analyzer = getattr(request, 'network_analyzer', None)
    if not analyzer:
        analyzer = NetworkAnalyzer()
        request.network_analyzer = analyzer

    # Get available interfaces
    interfaces = get_network_interfaces()

    # Get stats for the first interface if available
    stats = {}
    if interfaces:
        stats = get_network_stats(interfaces[0])

    # Get recent traffic (last 100 records)
    recent_traffic = NetworkTraffic.objects.order_by('-timestamp')[:100]

    # Get alerts (last 50 records)
    alerts = NetworkAlert.objects.order_by('-created_at')[:50]

    # Get rules
    rules = NetworkRule.objects.all()
    is_capturing = hasattr(request, 'network_analyzer_running') and request.network_analyzer_running

    context = {
        'interfaces': interfaces,
        'stats': stats,
        'recent_traffic': recent_traffic,
        'alerts': alerts,
        'rules': rules,
        'is_capturing': is_capturing
    }

    return render(request, '../templates/toolkit/network_home.html', context)


@csrf_exempt
@login_required(login_url='login')
@require_http_methods(["POST"])
def start_network_capture(request):
    interface = request.POST.get('interface')

    analyzer = getattr(request, 'network_analyzer', None)
    if not analyzer:
        analyzer = NetworkAnalyzer(interface=interface)
        request.network_analyzer = analyzer

    if analyzer.start_capture():
        request.network_analyzer_running = True
        messages.success(request, "Network capture started successfully")
    else:
        messages.error(request, "Network capture is already running")

    return redirect('network_home')


@csrf_exempt
@login_required(login_url='login')
@require_http_methods(["POST"])
def stop_network_capture(request):
    analyzer = getattr(request, 'network_analyzer', None)
    if analyzer:
        analyzer.stop_capture()
        request.network_analyzer_running = False
        messages.success(request, "Network capture stopped successfully")
    else:
        messages.error(request, "No active network capture to stop")

    return redirect('network_home')


@csrf_exempt
@login_required(login_url='login')
def network_traffic_list(request):
    # Get filter parameters
    protocol = request.GET.get('protocol')
    malicious = request.GET.get('malicious')
    time_range = request.GET.get('time_range', '24h')

    # Build query
    query = {}

    if protocol and protocol != 'all':
        query['protocol'] = protocol

    if malicious == 'true':
        query['is_malicious'] = True
    elif malicious == 'false':
        query['is_malicious'] = False

    # Calculate time range
    now = timezone.now()
    if time_range == '1h':
        start_time = now - timedelta(hours=1)
    elif time_range == '6h':
        start_time = now - timedelta(hours=6)
    elif time_range == '12h':
        start_time = now - timedelta(hours=12)
    elif time_range == '1d':
        start_time = now - timedelta(days=1)
    elif time_range == '7d':
        start_time = now - timedelta(days=7)
    else:
        start_time = now - timedelta(days=1)

    query['timestamp__gte'] = start_time

    # Get filtered traffic
    traffic = NetworkTraffic.objects.filter(**query).order_by('-timestamp')

    # Pagination
    paginator = Paginator(traffic, 50)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'page_obj': page_obj,
        'protocol': protocol or 'all',
        'malicious': malicious or 'all',
        'time_range': time_range
    }

    return render(request, '../templates/toolkit/network_traffic_list.html', context)


@csrf_exempt
@login_required(login_url='login')
def network_alerts_list(request):
    # Get filter parameters
    severity = request.GET.get('severity')
    status = request.GET.get('status')
    time_range = request.GET.get('time_range', '24h')

    # Build query
    query = {}

    if severity and severity != 'all':
        query['severity'] = severity

    if status and status != 'all':
        query['status'] = status

    # Calculate time range
    now = timezone.now()
    if time_range == '1h':
        start_time = now - timedelta(hours=1)
    elif time_range == '6h':
        start_time = now - timedelta(hours=6)
    elif time_range == '12h':
        start_time = now - timedelta(hours=12)
    elif time_range == '1d':
        start_time = now - timedelta(days=1)
    elif time_range == '7d':
        start_time = now - timedelta(days=7)
    else:
        start_time = now - timedelta(days=1)

    query['created_at__gte'] = start_time

    # Get filtered alerts
    alerts = NetworkAlert.objects.filter(**query).order_by('-created_at')

    # Pagination
    paginator = Paginator(alerts, 50)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'page_obj': page_obj,
        'severity': severity or 'all',
        'status': status or 'all',
        'time_range': time_range
    }

    return render(request, '../templates/toolkit/network_alerts_list.html', context)


@csrf_exempt
@login_required(login_url='login')
@require_http_methods(["POST"])
def update_alert_status(request, alert_id):
    try:
        alert = NetworkAlert.objects.get(id=alert_id)
        new_status = request.POST.get('status')

        if new_status in [choice[0] for choice in NetworkAlert.STATUS_CHOICES]:
            alert.status = new_status
            if new_status == 'resolved':
                alert.resolved_at = timezone.now()
                alert.resolved_by = request.user
            alert.save()
            messages.success(request, f"Alert status updated to {new_status}")
        else:
            messages.error(request, "Invalid status provided")
    except NetworkAlert.DoesNotExist:
        messages.error(request, "Alert not found")

    return redirect('network_alerts_list')


@csrf_exempt
@login_required(login_url='login')
def network_rules_list(request):
    rules = NetworkRule.objects.all().order_by('-created_at')
    context = {
        'rules': rules
    }
    return render(request, '../templates/toolkit/network_rules_list.html', context)


@csrf_exempt
@login_required(login_url='login')
def add_network_rule(request):
    if request.method == 'POST':
        try:
            NetworkRule.objects.create(
                name=request.POST.get('name'),
                description=request.POST.get('description'),
                rule_type=request.POST.get('rule_type'),
                pattern=request.POST.get('pattern'),
                action=request.POST.get('action'),
                severity=request.POST.get('severity'),
                is_active=request.POST.get('is_active') == 'on',
                created_by=request.user
            )
            messages.success(request, "Rule added successfully")
            return redirect('network_rules_list')
        except Exception as e:
            messages.error(request, f"Error adding rule: {e}")

    return render(request, '../templates/toolkit/add_network_rule.html')


@csrf_exempt
@login_required(login_url='login')
@require_http_methods(["POST"])
def toggle_network_rule(request, rule_id):
    try:
        rule = NetworkRule.objects.get(id=rule_id)
        rule.is_active = not rule.is_active
        rule.save()
        return JsonResponse({'success': True, 'is_active': rule.is_active})
    except NetworkRule.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Rule not found'}, status=404)


@csrf_exempt
@login_required(login_url='login')
def network_dashboard_data(request):
    # Get stats for dashboard
    total_traffic = NetworkTraffic.objects.count()
    malicious_traffic = NetworkTraffic.objects.filter(is_malicious=True).count()
    open_alerts = NetworkAlert.objects.filter(status='open').count()

    # Get traffic by protocol
    protocol_stats = NetworkTraffic.objects.values('protocol').annotate(
        count=models.Count('id'),
        malicious=models.Sum(models.Case(
            models.When(is_malicious=True, then=1),
            default=0,
            output_field=models.IntegerField()
        ))
    ).order_by('-count')

    # Get alert counts by severity
    alert_stats = NetworkAlert.objects.values('severity').annotate(
        count=models.Count('id')
    ).order_by('severity')

    data = {
        'total_traffic': total_traffic,
        'malicious_traffic': malicious_traffic,
        'open_alerts': open_alerts,
        'protocol_stats': list(protocol_stats),
        'alert_stats': list(alert_stats)
    }

    return JsonResponse(data)
