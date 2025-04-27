import subprocess
import platform
from scapy.arch import get_if_list


def get_network_interfaces():
    """Get available network interfaces"""
    return get_if_list()


def get_interface_ip(interface):
    """Get IP address of a specific interface"""
    try:
        if platform.system() == 'Windows':
            cmd = ['ipconfig']
            output = subprocess.check_output(cmd).decode('utf-8', errors='ignore')

            # Parse output for the specific interface
            for line in output.split('\n'):
                if interface in line:
                    next_lines = output.split('\n')[output.split('\n').index(line):]
                    for next_line in next_lines:
                        if 'IPv4 Address' in next_line or 'IP Address' in next_line:
                            return next_line.split(':')[-1].strip()
        else:
            cmd = ['ifconfig', interface]
            output = subprocess.check_output(cmd).decode('utf-8', errors='ignore')

            # Parse output for IP address
            for line in output.split('\n'):
                if 'inet ' in line:
                    return line.split()[1]
    except Exception as e:
        print(f"Error getting interface IP: {e}")
    return None


def get_network_stats(interface=None):
    """Get network statistics for an interface"""
    stats = {
        'packets_sent': 0,
        'packets_received': 0,
        'bytes_sent': 0,
        'bytes_received': 0,
        'error_count': 0
    }

    try:
        if platform.system() == 'Windows':
            cmd = ['netstat', '-e']
            output = subprocess.check_output(cmd).decode('utf-8', errors='ignore')

            # Parse output for statistics
            for line in output.split('\n'):
                if 'Bytes' in line and 'Received' in line and 'Sent' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        stats['bytes_received'] = int(parts[1].replace(',', ''))
                        stats['bytes_sent'] = int(parts[3].replace(',', ''))
                elif 'Unicast packets' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        stats['packets_received'] = int(parts[1].replace(',', ''))
                        stats['packets_sent'] = int(parts[3].replace(',', ''))
        else:
            if interface:
                cmd = ['ifconfig', interface]
            else:
                cmd = ['ifconfig']

            output = subprocess.check_output(cmd).decode('utf-8', errors='ignore')

            # Parse output for statistics
            for line in output.split('\n'):
                if 'RX packets' in line:
                    parts = line.split()
                    stats['packets_received'] = int(parts[2])
                    stats['bytes_received'] = int(parts[5])
                elif 'TX packets' in line:
                    parts = line.split()
                    stats['packets_sent'] = int(parts[2])
                    stats['bytes_sent'] = int(parts[5])
                elif 'errors' in line:
                    parts = line.split()
                    stats['error_count'] = int(parts[2])
    except Exception as e:
        print(f"Error getting network stats: {e}")

    return stats


def test_network_connection():
    """Test basic network connectivity"""
    try:
        if platform.system() == 'Windows':
            cmd = ['ping', '-n', '1', '8.8.8.8']
        else:
            cmd = ['ping', '-c', '1', '8.8.8.8']

        subprocess.check_output(cmd)
        return True
    except subprocess.CalledProcessError:
        return False
    except Exception as e:
        print(f"Error testing network connection: {e}")
        return False