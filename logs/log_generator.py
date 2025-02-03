import time
import random
from faker import Faker
from datetime import datetime

# Log generation function
def generate_logs(log_file):
    """Simulates log generation by writing random logs, including attack patterns, to a file."""
    fake = Faker()

    # HTTP methods, status codes, and URLs
    http_methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]
    status_codes = [200, 201, 301, 302, 400, 401, 403, 404, 500, 503]

    normal_urls = ["/home", "/about", "/contact", "/products", "/login", "/register"]

    # Attack Patterns
    sql_injection_patterns = [
        "/products?id=' OR '1'='1",
        "/search?query='; DROP TABLE users; --",
        "/account?user=' UNION SELECT * FROM users; --"
    ]
    xss_patterns = [
        "/profile?input=<script>alert('XSS')</script>",
        "/comments?input=<img src='x' onerror='alert(1)'>",
        "/view?name=javascript:alert('XSS')"
    ]
    directory_traversal_patterns = [
        "/../../../etc/passwd",
        "/..%2f..%2f..%2fwindows/system32/cmd.exe",
        "/files?path=../../../../config.php"
    ]
    command_injection_patterns = [
        "/search?query=; ls -la",
        "/ping?host=127.0.0.1; rm -rf /",
        "/backup?cmd=| cat /etc/shadow"
    ]

    brute_force_ips = [fake.ipv4() for _ in range(3)]  # Fixed IPs for simulating brute-force attempts

    while True:
        # Randomly decide whether to generate a normal log or simulate an attack
        log_type = random.choices(
            ["normal", "brute_force", "ddos", "sql_injection", "xss", "dir_traversal", "cmd_injection"],
            weights=[97, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5],
            k=1
        )[0]

        ip = fake.ipv4()
        method = random.choice(http_methods)
        status = random.choice(status_codes)
        url = random.choice(normal_urls)
        response_size = random.randint(100, 10000)

        if log_type == "brute_force":
            ip = random.choice(brute_force_ips)
            url = "/login"
            status = 401
            for _ in range(random.randint(10, 15)):
                write_log_entry(log_file, ip, method, url, status, response_size)
                time.sleep(random.uniform(0.05, 0.2))

        elif log_type == "ddos":
            for _ in range(random.randint(50, 60)):
                write_log_entry(log_file, ip, method, url, status, response_size)
                time.sleep(random.uniform(0.01, 0.05))

        elif log_type == "sql_injection":
            url = random.choice(sql_injection_patterns)
            write_log_entry(log_file, ip, method, url, 500, response_size)

        elif log_type == "xss":
            url = random.choice(xss_patterns)
            write_log_entry(log_file, ip, method, url, 200, response_size)

        elif log_type == "dir_traversal":
            url = random.choice(directory_traversal_patterns)
            write_log_entry(log_file, ip, method, url, 403, response_size)

        elif log_type == "cmd_injection":
            url = random.choice(command_injection_patterns)
            write_log_entry(log_file, ip, method, url, 500, response_size)

        else:
            # Generate a normal log entry
            write_log_entry(log_file, ip, method, url, status, response_size)

        time.sleep(random.uniform(0.1, 1.0))


def write_log_entry(log_file, ip, method, url, status, response_size):
    """Write a formatted log entry to the file."""
    timestamp = datetime.now().strftime('%d/%b/%Y:%H:%M:%S %z')
    log_entry = (
        f"{ip} - - [{timestamp}] \"{method} {url} HTTP/1.1\" {status} {response_size}"
    )
    with open(log_file, "a") as file:
        file.write(log_entry + "\n")


if __name__ == "__main__":
    generate_logs("test_attack_logs.log")



