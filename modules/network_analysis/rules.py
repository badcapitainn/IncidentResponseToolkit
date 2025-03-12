malicious_ips = ["192.168.1.100", "10.0.0.50"]  # Example blacklisted IPs
sql_injection_patterns = [r"UNION.*SELECT", r"DROP TABLE", r"INSERT INTO"]  # SQL Injection patterns
port_scan_threshold = 10  # Number of connection attempts before triggering an alert
