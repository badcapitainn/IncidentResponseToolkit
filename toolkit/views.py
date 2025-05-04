import json
import os
import random
import threading
import time

from django.utils import timezone
from datetime import datetime, timedelta
from django.http import JsonResponse, HttpResponse
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
# -------------------------------network test imports --------------------------------------------
from .models import NetworkCapture, NetworkAlert, NetworkRule
from modules.network.capture import NetworkCapture as NetCapture
from modules.network.analysis import NetworkAnalyzer
from modules.network.rules import NetworkRuleManager
import logging


@csrf_exempt
@login_required(login_url='login')
def dashboard(request):
    watch_list_logs = WatchlistLogs.objects.all()
    alert_logs = AlertLogs.objects.all()

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

                request.session['network_capture'] = False
                return JsonResponse({'status': 'stopped'})
            except Exception as e:
                return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

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
        'is_capturing': request.session.get('network_capture', False)
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

        # Prepare statistics
        stats = {
            'total_packets': analyzer.stats.get('total_packets', 0),
            'start_time': datetime.fromtimestamp(analyzer.stats.get('start_time', time.time())),
            'end_time': datetime.fromtimestamp(analyzer.stats.get('end_time', time.time())),
            'protocol_distribution': analyzer.get_protocol_distribution(),
            'top_source_ips': analyzer.get_top_ips(type='source'),
            'top_dest_ips': analyzer.get_top_ips(type='dest'),
            'top_ports': analyzer.get_top_ports(),
            'protocol_chart': analyzer.generate_protocol_chart(),
            'timeline_chart': analyzer.generate_timeline_chart(),
            'alerts': alerts[:100],  # Limit to 100 most recent alerts
            'alerts_by_severity': {
                'critical': len([a for a in alerts if a['severity'] == 'critical']),
                'high': len([a for a in alerts if a['severity'] == 'high']),
                'medium': len([a for a in alerts if a['severity'] == 'medium']),
                'low': len([a for a in alerts if a['severity'] == 'low'])
            }
        }

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
