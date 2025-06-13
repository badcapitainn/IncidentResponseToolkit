import json
import os
import random
import shutil
import threading
import time
import requests

from django.core.paginator import Paginator
from django.db import transaction
from django.utils import timezone
from datetime import datetime, timedelta
from django.http import JsonResponse, HttpResponse, HttpResponseForbidden
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from modules.firewall.blocker import FirewallBlocker
from modules.log_module.utils import RealTimeLogMonitor
from .forms import RegisterForm
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from .models import AlertLogs, SuspiciousLogs, WatchlistLogs, MaliciousPackets, SuspiciousPackets, SystemMetrics, \
    MalwareDetectionResult, Quarantine, NetworkCapture, NetworkAlert, NetworkRule, BlockedIP, RecentActivity
from modules.malware_detection.scanner import MalwareScanner
from django.conf import settings
from django.core.files.storage import FileSystemStorage
from modules.network.capture import NetworkCapture as NetCapture
from modules.network.analysis import NetworkAnalyzer
from modules.network.rules import NetworkRuleManager
import logging
from .models import LogEntry, LogSource, LogAlert
from modules.log_module.core import LogAnalyzer

@csrf_exempt
@login_required(login_url='login')
def dashboard(request):
    alert_logs = AlertLogs.objects.all()
    network_alerts = NetworkAlert.objects.all()
    malware_alerts = MalwareDetectionResult.objects.all().filter(is_malicious=True)
    recent_activity = RecentActivity.objects.all().order_by('-timestamp')[:5]

    
    log_alert_count: int = len([a for a in alert_logs])
    network_alert_count: int = len([a for a in network_alerts])
    malware_alert_count: int = len([a for a in malware_alerts])

    all_alert_count: int = log_alert_count + network_alert_count + malware_alert_count

    log_percentage: float = round(log_alert_count / all_alert_count * 100, 1)
    network_percentage: float = round(network_alert_count / all_alert_count * 100, 1)
    malware_percentage: float = round(malware_alert_count / all_alert_count * 100, 1)

    # Get the latest application-specific resource usage data
    resource_data = SystemMetrics.objects.filter(is_application_only=True).order_by('-timestamp')[
                    :30]  # Last 30 readings

    # Prepare data for the template
    timestamps = [data.timestamp.strftime('%H:%M:%S') for data in resource_data]
    cpu_data = [data.cpu_usage for data in resource_data]
    ram_data = [data.ram_used for data in resource_data]

    # For disk, we'll use read/write operations instead of percentage
    disk_read_data = [data.disk_read for data in resource_data]
    disk_write_data = [data.disk_write for data in resource_data]

    context = {
        "alert_logs": alert_logs,
        "timestamps": json.dumps(timestamps[::-1]),  # Reverse to show oldest first
        "cpu_data": json.dumps(cpu_data[::-1]),
        "ram_data": json.dumps(ram_data[::-1]),
        "disk_read_data": json.dumps(disk_read_data[::-1]),
        "disk_write_data": json.dumps(disk_write_data[::-1]),
        "latest_ram": resource_data[0].ram_used if resource_data else 0,
        "latest_disk_read": resource_data[0].disk_read if resource_data else 0,
        "latest_disk_write": resource_data[0].disk_write if resource_data else 0,
        "log_alert_count": log_alert_count,
        "network_alert_count": network_alert_count,
        "malware_alert_count": malware_alert_count,
        "all_alert_count": all_alert_count,
        "log_percentage": log_percentage,
        "network_percentage": network_percentage,
        "malware_percentage": malware_percentage,
        "recent_activity": recent_activity
    }
    template = '../templates/toolkit/dashboard.html'
    return render(request, template, context)


# ------------------------------------------- log analysis views -------------------------------------------------------

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
def log_module(request):
    # Initialize analyzer
    analyzer = LogAnalyzer()

    # Get statistics
    stats = analyzer.get_log_statistics()

    # Get recent logs
    recent_logs = LogEntry.objects.all().order_by('-timestamp')[:50]

    # Get active alerts
    active_alerts = LogAlert.objects.filter(resolved=False).order_by('-timestamp')[:10]

    context = {
        'stats': stats,
        'recent_logs': recent_logs,
        'active_alerts': active_alerts,
        'log_sources': LogSource.objects.all(),
    }

    return render(request, '../templates/toolkit/log_analysis_module.html', context)


@csrf_exempt
@login_required(login_url='login')
def log_details(request):
    # Get filter parameters
    level_filter = request.GET.get('level', '')
    source_filter = request.GET.get('source', '')
    search_query = request.GET.get('search', '')

    # Build query
    logs = LogEntry.objects.all().order_by('-timestamp')
    sources = LogSource.objects.all()  # Get all sources for the filter dropdown

    if level_filter:
        logs = logs.filter(level=level_filter)
    if source_filter:
        logs = logs.filter(source__name=source_filter)
    if search_query:
        logs = logs.filter(message__icontains=search_query)

    # Pagination
    paginator = Paginator(logs, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'page_obj': page_obj,
        'level_filter': level_filter,
        'source_filter': source_filter,
        'search_query': search_query,
        'log_sources': sources,
        'LEVEL_CHOICES': LogEntry.LEVEL_CHOICES
    }

    return render(request, '../templates/toolkit/log_details.html', context)


@csrf_exempt
@login_required(login_url='login')
def log_alerts(request):
    # Get filter parameters
    resolved_filter = request.GET.get('resolved', 'false') == 'true'

    alerts = LogAlert.objects.all().order_by('-timestamp')

    if not resolved_filter:
        alerts = alerts.filter(resolved=False)

    # Pagination
    paginator = Paginator(alerts, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'page_obj': page_obj,
        'resolved_filter': resolved_filter,
    }

    return render(request, '../templates/toolkit/log_alerts.html', context)


@csrf_exempt
@login_required(login_url='login')
def resolve_alert(request, alert_id):
    if request.method == 'POST':
        try:
            alert = LogAlert.objects.get(id=alert_id)
            alert.resolve(request.user)
            # Update Recent activities
            add_recent_activity(request, activity = "Log Alert Resolved", module = "Log")
            return JsonResponse({'status': 'success'})
        except LogAlert.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Alert not found'}, status=404)
    return JsonResponse({'status': 'error', 'message': 'Invalid method'}, status=400)


@csrf_exempt
@login_required(login_url='login')
def upload_log_file(request):
    if request.method == 'POST' and request.FILES.get('log_file'):
        log_file = request.FILES['log_file']
        source_name = request.POST.get('source_name', 'uploaded')

        # Save to temp location
        temp_path = os.path.join(settings.MEDIA_ROOT, 'temp_logs', log_file.name)
        os.makedirs(os.path.dirname(temp_path), exist_ok=True)

        with open(temp_path, 'wb+') as destination:
            for chunk in log_file.chunks():
                destination.write(chunk)

        # Process the file
        analyzer = LogAnalyzer()
        success = analyzer.process_log_file(temp_path, source_name)

        # Clean up
        os.remove(temp_path)

        if success:
            # Update Recent activities
            add_recent_activity(activity = "Log File Analysed", module = "Log")
            return JsonResponse({'status': 'success'})
        else:
            return JsonResponse({'status': 'error', 'message': 'Failed to process log file'}, status=500)

    return JsonResponse({'status': 'error', 'message': 'Invalid request'}, status=400)


@csrf_exempt
@login_required(login_url='login')
def log_stats_api(request):
    analyzer = LogAnalyzer()
    stats = analyzer.get_log_statistics()
    return JsonResponse(stats)


# Global monitor instance
_monitor_instance = None


def get_log_monitor():
    global _monitor_instance
    if _monitor_instance is None:
        from modules.log_module.utils import RealTimeLogMonitor
        _monitor_instance = RealTimeLogMonitor()
    return _monitor_instance


@csrf_exempt
@login_required(login_url='login')
def start_monitoring(request):
    monitor = get_log_monitor()
    if request.method == 'POST':
        monitor.start()
        # Update Recent activities
        add_recent_activity(request, activity = "Log Monitoring Started", module = "Log")
        return JsonResponse({'status': 'started'})
    return JsonResponse({'status': 'error'}, status=400)


@csrf_exempt
@login_required(login_url='login')
def stop_monitoring(request):
    monitor = get_log_monitor()
    if request.method == 'POST':
        monitor.stop()
        # Update Recent activities
        add_recent_activity(request, activity = "Log Monitoring Stopped", module = "Log")
        return JsonResponse({'status': 'stopped'})
    return JsonResponse({'status': 'error'}, status=400)


@csrf_exempt
@login_required(login_url='login')
def monitoring_status(request):
    monitor = get_log_monitor()
    return JsonResponse({
        'status': 'running' if monitor.running else 'stopped',
        'watch_dirs': monitor.watch_dirs
    })


@login_required
def blocked_ips(request):
    active_blocks = BlockedIP.objects.filter(unblocked=False)
    inactive_blocks = BlockedIP.objects.filter(unblocked=True)

    if request.method == 'POST' and 'unblock_ip' in request.POST:
        ip_address = request.POST.get('ip_address')
        try:
            blocker = FirewallBlocker()
            if blocker.unblock_ip(ip_address):
                # Update Recent activities
                add_recent_activity(activity = "IP unblocked", module = "Log")
                messages.success(request, f"IP {ip_address} has been unblocked")
            else:
                messages.error(request, f"Failed to unblock IP {ip_address}")
        except Exception as e:
            messages.error(request, f"Error: {str(e)}")
        return redirect('blocked_ips')

    return render(request, '../templates/toolkit/blocked_ips.html', {
        'active_blocks': active_blocks,
        'inactive_blocks': inactive_blocks
    })


def check_blocked_ip(view_func):
    def wrapper(request, *args, **kwargs):
        blocker = FirewallBlocker()
        client_ip = request.META.get('REMOTE_ADDR')
        
        if client_ip and blocker.is_blocked(client_ip):
            return HttpResponseForbidden("IP blocked")
            
        return view_func(request, *args, **kwargs)
    return wrapper
# -------------------------------------------- Malware Views -----------------------------------------------------------

@csrf_exempt
@login_required(login_url='login')
def malware_detection(request):
    if request.method == 'POST':
        if 'file_scan' in request.FILES:
            # Update Recent activities
            add_recent_activity(request, activity = "Malware Scan Completed", module = "Malware")
            return handle_file_scan(request)
        elif 'directory_path' in request.POST:
            # Update Recent activities
            add_recent_activity(request, activity = "Malware Scan Completed", module = "Malware")
            return handle_directory_scan(request)

    quarantined_files = Quarantine.objects.filter(restored=False).select_related('detection_result')
    recent_scans = MalwareDetectionResult.objects.all().order_by('-scan_time')[:10]
    return render(request, '../templates/toolkit/malware_detection.html', {
        'recent_scans': recent_scans,
        'quarantined_files': quarantined_files
    })


@transaction.atomic
def handle_file_scan(request):
    uploaded_file = request.FILES['file_scan']
    fs = FileSystemStorage()

    try:
        # Save the uploaded file temporarily
        filename = fs.save(uploaded_file.name, uploaded_file)
        file_path = os.path.join(settings.MEDIA_ROOT, filename)

        # Scan the file
        scanner = MalwareScanner()
        matches = scanner.scan_file(file_path)

        if matches:
            # Create detection record
            result = MalwareDetectionResult.objects.create(
                file_path=file_path,
                scan_time=datetime.now(),
                is_malicious=True,
                malware_type=", ".join([m.rule for m in matches]),
                details=str(matches),
                detected_by=request.user
            )

            # Quarantine the file
            try:
                quarantine_record = scanner.quarantine_file(file_path, result)
                messages.warning(request,
                                 f"Malware detected and quarantined: {result.malware_type}\n"
                                 f"File moved to: {quarantine_record.quarantine_path}"
                                 )
                logger.info(f"Quarantined file: {file_path} to {quarantine_record.quarantine_path}")
            except Exception as quarantine_error:
                logger.error(f"Quarantine failed: {str(quarantine_error)}")
                messages.error(request, f"Malware detected but quarantine failed: {str(quarantine_error)}")
                # Delete the temp file if quarantine failed
                if os.path.exists(file_path):
                    os.remove(file_path)
                raise quarantine_error
        else:
            result = MalwareDetectionResult.objects.create(
                file_path=file_path,
                scan_time=datetime.now(),
                is_malicious=False,
                detected_by=request.user
            )
            messages.success(request, "No malware detected in the file.")
            # Clean up the temporary file
            if os.path.exists(file_path):
                os.remove(file_path)

    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        messages.error(request, f"Scanning error: {str(e)}")
        # Clean up if something went wrong
        if 'file_path' in locals() and os.path.exists(file_path):
            os.remove(file_path)

    return redirect('malware_detection')


@transaction.atomic
def handle_directory_scan(request):
    directory_path = request.POST['directory_path']

    if not os.path.isdir(directory_path):
        messages.error(request, "Invalid directory path.")
        return redirect('malware_detection')

    scanner = MalwareScanner()
    try:
        results = scanner.scan_directory(directory_path)

        if results:
            quarantined_count = len(results)
            messages.warning(request,
                             f"Found {quarantined_count} malicious files in the directory.\n"
                             f"All detected files have been quarantined."
                             )
            logger.info(f"Directory scan quarantined {quarantined_count} files from {directory_path}")
        else:
            messages.success(request, "No malware detected in the directory.")

    except Exception as e:
        logger.error(f"Directory scan error: {str(e)}")
        messages.error(request, f"Directory scanning error: {str(e)}")

    return redirect('malware_detection')


@csrf_exempt
@require_POST
@login_required(login_url='login')
def delete_file(request):
    """Permanently delete a quarantined file"""
    file_id = request.POST.get('file_id')
    try:
        quarantine = Quarantine.objects.get(id=file_id)
        if os.path.exists(quarantine.quarantine_path):
            os.remove(quarantine.quarantine_path)
        quarantine.delete()
         # Update Recent activities
        add_recent_activity(request, activity = "Quarantined File Deleted", module = "Malware")
        return JsonResponse({'status': 'success'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)


@csrf_exempt
@require_POST
@login_required(login_url='login')
def restore_file(request):
    """Restore a file from quarantine"""
    file_id = request.POST.get('file_id')
    try:
        quarantine = Quarantine.objects.get(id=file_id)

        # Check if original location is available
        if os.path.exists(quarantine.original_path):
            return JsonResponse({
                'status': 'error',
                'message': 'Original file already exists'
            }, status=400)

        # Move file back
        shutil.move(quarantine.quarantine_path, quarantine.original_path)

        # Update record
        quarantine.restored = True
        quarantine.restored_time = datetime.now()
        quarantine.save()
        # Update Recent activities
        add_recent_activity(request, activity = "Quarantined File Restored", module = "Malware")

        return JsonResponse({'status': 'success'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)


# --------------------------------------------- Auth Views -------------------------------------------------------------

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
             # Update Recent activities
            add_recent_activity(request, activity = "New User Added", module = "User")
            return redirect('dashboard')

    context = {'form': form}
    template = '../templates/toolkit/registration.html'
    return render(request, template, context)


def user_logout(request):
    logout(request)
    return redirect('login')


# -------------------------------------------- network views -----------------------------------------------------------

@csrf_exempt
@login_required(login_url='login')
def network_module(request):
    demo_mode = request.GET.get('demo', False)

    if demo_mode:
        test_dir = os.path.join(settings.BASE_DIR, 'test_captures')
        os.makedirs(test_dir, exist_ok=True)
        test_file = os.path.join(test_dir, f'demo_{int(time.time())}.pcap')

        from modules.network.packet_generator import PacketGenerator
        print("Generating demo packets...")  # Debug output
        PacketGenerator.generate_pcap_file(test_file, packet_count=random.randint(50, 150))

        # Verify file was created
        if not os.path.exists(test_file):
            print("Error: PCAP file not created!")  # Debug output
            return HttpResponse("Error generating demo data", status=500)

        print(f"Generated {os.path.getsize(test_file)} bytes of demo data")  # Debug output

        # Create demo capture record
        capture = NetworkCapture.objects.create(
            user=request.user,
            start_time=datetime.now() - timedelta(minutes=5),
            end_time=datetime.now(),
            packet_count=os.path.getsize(test_file) // 100,  # Approximate count
            capture_file=test_file,
            is_active=False
        )

        return redirect('network_stats', capture_id=capture.id)
    if request.method == 'POST' and request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        action = request.POST.get('action')

        if action == 'start':
            # Check if there's already an active capture
            if NetworkCapture.objects.filter(user=request.user, is_active=True).exists():
                return JsonResponse({'status': 'error', 'message': 'Capture already running'}, status=400)

            # Create new capture
            active_capture = NetworkCapture.objects.create(
                user=request.user,
                is_active=True
            )
             # Update Recent activities
            add_recent_activity(request, activity = "Network Scan Started", module = "Network")

            

            # Start actual capture (in a real implementation, you'd start a background task)
            try:
                net_capture = NetCapture()
                net_capture.start_capture()
                request.session['network_capture'] = True
                return JsonResponse({'status': 'started'})
            except Exception as e:
                active_capture.delete()
                return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

        elif action == 'stop':
            active_capture = NetworkCapture.objects.filter(user=request.user, is_active=True).first()
            if not active_capture:
                return JsonResponse({'status': 'error', 'message': 'No active capture'}, status=400)

            # Stop actual capture
            try:
                net_capture = NetCapture()
                net_capture.stop_capture()

                # Update database record
                active_capture.end_time = datetime.now()
                active_capture.is_active = False
                active_capture.packet_count = net_capture.stats['total_packets']
                active_capture.save()

                # Save alerts to database
                for alert in net_capture.alerts:
                    NetworkAlert.objects.create(
                        capture=active_capture,
                        rule_id=alert['rule_id'],
                        rule_name=alert['rule_name'],
                        severity=alert['severity'],
                        src_ip=alert['packet'].get('src_ip'),
                        dst_ip=alert['packet'].get('dst_ip'),
                        protocol=alert['packet'].get('protocol_name'),
                        src_port=alert['packet'].get('src_port'),
                        dst_port=alert['packet'].get('dst_port'),
                        packet_size=alert['packet'].get('size'),
                        details=alert['packet']
                    )
                
                # Update Recent activities
                add_recent_activity(request, activity = "Network Scan Stop", module = "Network")

                request.session['network_capture'] = False
                return JsonResponse({'status': 'stopped'})
            except Exception as e:
                return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

    active_capture = NetworkCapture.objects.filter(user=request.user, is_active=True).first()
    captures = NetworkCapture.objects.filter(user=request.user).order_by('-start_time')

    # Get alerts for active capture or most recent capture
    if active_capture:
        recent_alerts = NetworkAlert.objects.filter(capture=active_capture).order_by('-timestamp')[:10]
    elif captures.exists():
        recent_alerts = NetworkAlert.objects.filter(capture=captures.first()).order_by('-timestamp')[:10]
    else:
        recent_alerts = []

    # GET request handling remains the same
    active_capture = NetworkCapture.objects.filter(user=request.user, is_active=True).first()
    captures = NetworkCapture.objects.filter(user=request.user).order_by('-start_time')
    alerts = NetworkAlert.objects.filter(capture=active_capture).order_by('-timestamp') if active_capture else []
    rules = NetworkRule.objects.all()

    context = {
        'active_capture': active_capture,
        'captures': captures,
        'alerts': alerts[:10],
        'rules': rules,
        'is_capturing': request.session.get('network_capture', False),
        'recent_alerts': recent_alerts,
    }

    return render(request, '../templates/toolkit/network_module.html', context)


logger = logging.getLogger(__name__)


@csrf_exempt
@login_required(login_url='login')
def network_stats(request, capture_id):
    try:
        # Get the capture record
        capture = NetworkCapture.objects.get(id=capture_id, user=request.user)

        # Verify capture file exists
        if not os.path.exists(capture.capture_file):
            logger.error(f"Capture file not found: {capture.capture_file}")
            return render(request, 'toolkit/network_stats.html', {
                'error': 'Capture file not found',
                'capture': capture
            })

        # Initialize analyzer and load packets
        analyzer = NetworkAnalyzer(capture.capture_file)
        analyzer.load_pcap()

        # Initialize rule manager and check all packets
        rule_manager = NetworkRuleManager()
        alerts = []

        # Debug: Print packet and rule matching info
        logger.debug(f"Analyzing {len(analyzer.packets)} packets")
        for i, packet in enumerate(analyzer.packets):
            matched_rules = rule_manager.check_packet(packet)
            if matched_rules:
                logger.debug(f"Packet {i} matched rules: {[r.name for r in matched_rules]}")
                for rule in matched_rules:
                    alerts.append({
                        'timestamp': datetime.fromtimestamp(packet.get('timestamp', time.time())),
                        'rule_name': rule.name,
                        'severity': rule.severity,
                        'src_ip': packet.get('src_ip', ''),
                        'src_port': packet.get('src_port', ''),
                        'dst_ip': packet.get('dst_ip', ''),
                        'dst_port': packet.get('dst_port', ''),
                        'protocol': packet.get('protocol_name', ''),
                        'details': {
                            'flags': packet.get('flags', ''),
                            'size': packet.get('size', 0),
                            'payload_preview': str(packet.get('payload', ''))[:100] if 'payload' in packet else None
                        }
                    })

        # Get analysis summary from analyzer
        analysis_summary = analyzer.get_analysis_summary()

        # Prepare statistics
        stats = {
            'total_packets': analysis_summary['total_packets'],
            'start_time': datetime.fromtimestamp(analysis_summary['start_time']),
            'end_time': datetime.fromtimestamp(analysis_summary['end_time']),
            'protocol_distribution': analysis_summary['protocol_distribution'],
            'timeline': analysis_summary['timeline'],
            'top_source_ips': analysis_summary['top_source_ips'],
            'top_dest_ips': analysis_summary['top_dest_ips'],
            'top_ports': analysis_summary['top_ports'],
            'alerts': alerts[:100],  # Limit to 100 most recent alerts
            'alerts_by_severity': {
                'critical': len([a for a in alerts if a['severity'] == 'critical']),
                'high': len([a for a in alerts if a['severity'] == 'high']),
                'medium': len([a for a in alerts if a['severity'] == 'medium']),
                'low': len([a for a in alerts if a['severity'] == 'low'])
            }
        }

        # Prepare data for JavaScript charts
        protocol_labels = list(stats['protocol_distribution'].keys())
        protocol_data = list(stats['protocol_distribution'].values())
        
        # Sort timeline data by time
        sorted_timeline = sorted(stats['timeline'].items())
        timeline_labels = [item[0] for item in sorted_timeline]
        timeline_data = [item[1] for item in sorted_timeline]

        # Save alerts to database
        for alert in alerts[:100]:  # Save only first 100 alerts
            NetworkAlert.objects.create(
                capture=capture,
                timestamp=alert['timestamp'],
                rule_name=alert['rule_name'],
                severity=alert['severity'],
                src_ip=alert['src_ip'],
                dst_ip=alert['dst_ip'],
                src_port=alert['src_port'],
                dst_port=alert['dst_port'],
                protocol=alert['protocol'],
                details=alert['details']
            )

        return render(request, 'toolkit/network_stats.html', {
            'capture': capture,
            'stats': stats,
            'protocol_labels': protocol_labels,
            'protocol_data': protocol_data,
            'timeline_labels': timeline_labels,
            'timeline_data': timeline_data,
            'alerts': alerts[:50]  # Only show 50 most recent in template
        })

    except NetworkCapture.DoesNotExist:
        logger.error(f"Capture not found: {capture_id}")
        return render(request, 'toolkit/network_stats.html', {
            'error': 'Capture not found'
        })
    except Exception as e:
        logger.error(f"Error analyzing capture: {str(e)}")
        return render(request, 'toolkit/network_stats.html', {
            'error': f'Error analyzing capture: {str(e)}'
        })

@csrf_exempt
@login_required(login_url='login')
def packet_details(request, capture_id):
    capture = NetworkCapture.objects.get(id=capture_id, user=request.user)
    analyzer = NetworkAnalyzer(capture.capture_file)
    analyzer.load_pcap()

    packets = analyzer.get_packet_dataframe().to_dict('records')

    return render(request, '../templates/toolkit/packet_details.html', {
        'capture': capture,
        'packets': packets[:100]  # Limit to 100 packets for display
    })


@csrf_exempt
@login_required(login_url='login')
def add_network_rule(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description')
        condition = request.POST.get('condition')
        severity = request.POST.get('severity', 'medium')

        NetworkRule.objects.create(
            name=name,
            description=description,
            condition=condition,
            severity=severity
        )

        return redirect('network_module')

    return render(request, '../templates/toolkit/add_rule.html')


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

@require_POST
@csrf_exempt
@login_required(login_url='login')
def resolve_alert(request, alert_id):
    try:
        alert = NetworkAlert.objects.get(id=alert_id, capture__user=request.user)
        action = request.POST.get('action')
        notes = request.POST.get('notes', '')
        block_duration = request.POST.get('block_duration', '1h')
        
        result = ""
        success = True
        
        # Implement actual response actions
        if action == 'block_ip':
            # Call firewall API to block the IP
            try:
                response = requests.post(
                    'https://your-firewall-api/block',
                    json={
                        'ip': alert.src_ip,
                        'duration': block_duration,
                        'reason': f"Security alert: {alert.rule_name}"
                    },
                    headers={'Authorization': 'Bearer YOUR_API_KEY'}
                )
                if response.status_code == 200:
                    result = f"Blocked {alert.src_ip} for {block_duration}"
                else:
                    result = f"Failed to block {alert.src_ip}: {response.text}"
                    success = False
            except Exception as e:
                result = f"Error blocking IP: {str(e)}"
                success = False
                
        elif action == 'quarantine_host':
            # Call endpoint management system
            try:
                response = requests.post(
                    'https://your-endpoint-api/quarantine',
                    json={
                        'host': alert.src_ip,
                        'reason': f"Security alert: {alert.rule_name}"
                    }
                )
                if response.status_code == 200:
                    result = f"Quarantined host {alert.src_ip}"
                else:
                    result = f"Failed to quarantine host: {response.text}"
                    success = False
            except Exception as e:
                result = f"Error quarantining host: {str(e)}"
                success = False
                
        elif action == 'disable_port':
            # Call network device API
            try:
                response = requests.post(
                    'https://your-network-api/disable_port',
                    json={
                        'ip': alert.dst_ip,
                        'port': alert.dst_port,
                        'reason': f"Security alert: {alert.rule_name}"
                    }
                )
                if response.status_code == 200:
                    result = f"Disabled port {alert.dst_port} on {alert.dst_ip}"
                else:
                    result = f"Failed to disable port: {response.text}"
                    success = False
            except Exception as e:
                result = f"Error disabling port: {str(e)}"
                success = False
                
        else:  # alert_only
            result = "Created ticket for manual investigation"
        
        # Update alert status
        if success:
            alert.status = 'resolved'
            alert.resolution = f"{action}: {result}\nNotes: {notes}"
            alert.resolved_by = request.user
            alert.resolved_at = timezone.now()
            alert.save()
        
        return JsonResponse({
            'status': 'success' if success else 'error',
            'message': result,
            'alert_id': alert_id
        })
        
    except NetworkAlert.DoesNotExist:
        return JsonResponse({
            'status': 'error',
            'message': 'Alert not found'
        }, status=404)
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)


#------------------------- other views --------------------------------------------
@login_required(login_url = 'login')
def add_recent_activity(request, activity: str, module: str) -> None:
    recent_activity = RecentActivity.objects.create(
                timestamp = datetime.now(),
                activity = activity,
                module = module,
            )
            