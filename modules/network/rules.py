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
            # Port Scan Detection (matches SYN scans to multiple ports)
            {
                'id': 'rule-port-scan',
                'name': 'Port Scan Detected',
                'condition': "packet.get('flags', 0) == 2 and packet.get('dst_port', 0) in [21, 22, 23, 25, 80, 443, 3389, 8080] and packet.get('dst_ip', '') == '192.168.1.1'",
                'severity': 'high'
            },

            # DDoS Detection (matches SYN flood to specific IP)
            {
                'id': 'rule-ddos',
                'name': 'Possible DDoS Attack',
                'condition': "packet.get('dst_ip', '') == '10.0.0.1' and packet.get('protocol_name', '') == 'TCP' and packet.get('flags', 0) == 2",
                'severity': 'critical'
            },

            # Brute Force Detection (matches SSH attempts)
            {
                'id': 'rule-brute-force',
                'name': 'Brute Force Attempt',
                'condition': "packet.get('dst_port', 0) == 22 and 'SSH-2.0' in str(packet.get('payload', ''))",
                'severity': 'high'
            },

            # Malware C2 Detection
            {
                'id': 'rule-malware-c2',
                'name': 'Possible Malware C2 Traffic',
                'condition': "packet.get('dst_ip', '') == '45.67.89.123' and packet.get('dst_port', 0) == 443",
                'severity': 'critical'
            },

            # SQL Injection Detection
            {
                'id': 'rule-sql-injection',
                'name': 'SQL Injection Attempt',
                'condition': "packet.get('dst_port', 0) == 80 and any(keyword in str(packet.get('payload', '')) for keyword in ['admin\\'--', '1=1', 'union select'])",
                'severity': 'high'
            },

            # XSS Detection
            {
                'id': 'rule-xss',
                'name': 'XSS Attempt',
                'condition': "packet.get('dst_port', 0) == 80 and any(keyword in str(packet.get('payload', '')) for keyword in ['<script>', 'onerror=', 'javascript:'])",
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