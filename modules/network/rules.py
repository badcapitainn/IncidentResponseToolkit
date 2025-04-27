# Standard rules for network traffic analysis
STANDARD_RULES = [
    {
        "name": "Unusual Port Scanning",
        "description": "Detects multiple connection attempts to different ports from a single source IP",
        "type": "PORT_SCAN",
        "threshold": 5,  # Number of different ports scanned
        "time_window": 60,  # Seconds
        "severity": "high",
        "action": "ALERT"
    },
    {
        "name": "Large Packet Flood",
        "description": "Detects an unusually large number of packets from a single source",
        "type": "PACKET_FLOOD",
        "threshold": 1000,  # Packets per second
        "time_window": 1,
        "severity": "high",
        "action": "ALERT"
    },
    {
        "name": "Suspicious TCP Flags",
        "description": "Detects packets with unusual TCP flag combinations (e.g., SYN+FIN)",
        "type": "TCP_FLAGS",
        "flags": ["SYN+FIN", "NULL", "XMAS"],
        "severity": "medium",
        "action": "ALERT"
    },
    {
        "name": "Known Malicious IP",
        "description": "Detects traffic to/from known malicious IP addresses",
        "type": "MALICIOUS_IP",
        "ips": [
            "185.143.223.0/24",
            "91.219.236.0/24",
            "45.9.148.0/24",
            "193.142.146.0/24"
        ],
        "severity": "critical",
        "action": "BLOCK"
    },
    {
        "name": "Common Exploit Ports",
        "description": "Detects traffic on commonly exploited ports",
        "type": "EXPLOIT_PORTS",
        "ports": [22, 23, 3389, 445, 1433, 3306, 8080, 80, 443],
        "severity": "medium",
        "action": "ALERT"
    },
    {
        "name": "DNS Tunneling Attempt",
        "description": "Detects unusually large DNS packets that may indicate tunneling",
        "type": "DNS_TUNNELING",
        "size_threshold": 512,  # Bytes
        "severity": "high",
        "action": "ALERT"
    },
    {
        "name": "HTTP Suspicious User Agent",
        "description": "Detects HTTP requests with suspicious user agents",
        "type": "HTTP_USER_AGENT",
        "patterns": [
            "sqlmap", "nmap", "metasploit", "nikto",
            "wget", "curl", "python-requests"
        ],
        "severity": "medium",
        "action": "ALERT"
    },
    {
        "name": "Suspicious PowerShell in HTTP",
        "description": "Detects PowerShell commands in HTTP traffic",
        "type": "HTTP_POWERSHELL",
        "patterns": [
            "powershell", "iex(", "Invoke-Expression",
            "DownloadString", "System.Net.WebClient"
        ],
        "severity": "high",
        "action": "ALERT"
    },
    {
        "name": "Suspicious File Extensions",
        "description": "Detects requests for suspicious file extensions",
        "type": "SUSPICIOUS_EXTENSIONS",
        "extensions": [
            ".php", ".asp", ".aspx", ".jsp",
            ".exe", ".dll", ".bat", ".cmd",
            ".ps1", ".sh", ".py", ".pl"
        ],
        "severity": "medium",
        "action": "ALERT"
    },
    {
        "name": "Unusual HTTP Methods",
        "description": "Detects unusual HTTP methods that may indicate exploitation attempts",
        "type": "HTTP_METHODS",
        "methods": ["PUT", "DELETE", "TRACE", "CONNECT", "PROPFIND"],
        "severity": "medium",
        "action": "ALERT"
    }
]


# Additional helper functions for rule processing
def load_rules_from_db():
    """Load rules from database if needed"""
    from toolkit.models import NetworkRule
    return list(NetworkRule.objects.filter(is_active=True).values())


def get_rule_by_type(rule_type):
    """Get rules of a specific type"""
    return [rule for rule in STANDARD_RULES if rule['type'] == rule_type]


def get_all_rules():
    """Combine standard rules with database rules"""
    standard_rules = STANDARD_RULES
    db_rules = load_rules_from_db()
    return standard_rules + db_rules
