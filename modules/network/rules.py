# config/toolkit/modules/network_analysis/rules.py
class NetworkRule:
    def __init__(self, rule_id, name, condition, severity='medium'):
        self.id = rule_id
        self.name = name
        self.condition = condition
        self.severity = severity

    def matches(self, packet):
        """Check if packet matches this rule"""
        try:
            return eval(self.condition, {}, {'packet': packet})
        except:
            return False


class NetworkRuleManager:
    def __init__(self):
        self.rules = []
        self.load_default_rules()

    def load_default_rules(self):
        """Load default detection rules including attack patterns"""
        default_rules = [
            # Original rules
            {
                'id': 'rule-001',
                'name': 'Suspicious Port Scan',
                'condition': "packet.get('flags', '') == 'S' and packet.get('dst_port', 0) in range(1, 1024)",
                'severity': 'high'
            },
            {
                'id': 'rule-002',
                'name': 'Possible DDoS',
                'condition': "packet.get('src_ip') == packet.get('dst_ip')",
                'severity': 'critical'
            },
            {
                'id': 'rule-003',
                'name': 'Unusual Protocol',
                'condition': "packet.get('protocol_name', '') not in ['TCP', 'UDP', 'ICMP']",
                'severity': 'medium'
            },
            {
                'id': 'rule-004',
                'name': 'High Port Activity',
                'condition': "packet.get('dst_port', 0) > 49151",
                'severity': 'low'
            },

            # New attack detection rules
            {
                'id': 'rule-101',
                'name': 'Port Scan Detected',
                'condition': "packet.get('flags', 0) == 2 and packet.get('dst_port', 0) in range(1, 1024)",
                'severity': 'high'
            },
            {
                'id': 'rule-102',
                'name': 'Possible DDoS Attack',
                'condition': "packet.get('dst_ip', '') == '10.0.0.1' and packet.get('protocol_name', '') == 'TCP' and packet.get('flags', 0) == 2",
                'severity': 'critical'
            },
            {
                'id': 'rule-103',
                'name': 'Brute Force Attempt',
                'condition': "packet.get('dst_port', 0) == 22 and 'SSH-2.0' in str(packet.get('payload', ''))",
                'severity': 'high'
            },
            {
                'id': 'rule-104',
                'name': 'SQL Injection Attempt',
                'condition': "packet.get('dst_port', 0) == 80 and any(keyword in str(packet.get('payload', '')) for keyword in ['--', '1=1', 'union select'])",
                'severity': 'high'
            },
            {
                'id': 'rule-105',
                'name': 'XSS Attempt',
                'condition': "packet.get('dst_port', 0) == 80 and any(keyword in str(packet.get('payload', '')) for keyword in ['<script>', 'onerror=', 'javascript:'])",
                'severity': 'medium'
            },
            {
                'id': 'rule-106',
                'name': 'Possible Malware C2 Traffic',
                'condition': "packet.get('dst_ip', '') == '45.67.89.123' and packet.get('dst_port', 0) == 443",
                'severity': 'critical'
            },
            {
                'id': 'rule-107',
                'name': 'DNS Tunneling Attempt',
                'condition': "packet.get('dst_port', 0) == 53 and len(str(packet.get('payload', ''))) > 512",
                'severity': 'medium'
            },
            {
                'id': 'rule-108',
                'name': 'HTTP Suspicious User Agent',
                'condition': "packet.get('dst_port', 0) == 80 and any(keyword in str(packet.get('payload', '').lower()) for keyword in ['nmap', 'sqlmap', 'nikto', 'metasploit'])",
                'severity': 'medium'
            }
        ]

        for rule_data in default_rules:
            self.add_rule(
                rule_data['id'],
                rule_data['name'],
                rule_data['condition'],
                rule_data['severity']
            )

    def add_rule(self, rule_id, name, condition, severity='medium'):
        """Add a new detection rule"""
        self.rules.append(NetworkRule(rule_id, name, condition, severity))

    def remove_rule(self, rule_id):
        """Remove a rule by ID"""
        self.rules = [rule for rule in self.rules if rule.id != rule_id]

    def get_rules(self):
        """Return all rules"""
        return self.rules

    def check_packet(self, packet):
        """Check packet against all rules"""
        return [rule for rule in self.rules if rule.matches(packet)]