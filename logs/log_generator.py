import time
import random
from faker import Faker
from datetime import datetime, timedelta


# Log generation function
def generate_logs(log_file):
    """Simulates log generation by writing random logs, including attack patterns, to a file."""

    # Initialize Faker
    fake = Faker()

    # Common HTTP methods and response codes
    http_methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]
    status_codes = [200, 201, 301, 302, 400, 401, 403, 404, 500, 503]

    normal_urls = ["/home", "/about", "/contact", "/products", "/login", "/register"]
    sql_injection_patterns = ["' OR '1'='1", "'; DROP TABLE users; --", "' UNION SELECT * FROM users; --"]
    xss_patterns = ["<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>", "javascript:alert('XSS')"]
    brute_force_ips = [fake.ipv4() for _ in range(3)]  # Fixed IPs for simulating brute-force attempts

    while True:
        # Randomly decide whether to generate a normal log or simulate an attack
        log_type = random.choices(
            ["normal", "brute_force", "ddos", "sql_injection", "xss"],
            weights=[60, 10, 10, 10, 10],  # Adjust weights to control frequency of each type
            k=1
        )[0]

        ip = fake.ipv4()
        method = random.choice(http_methods)
        status = random.choice(status_codes)
        url = random.choice(normal_urls)
        response_size = random.randint(100, 10000)

        if log_type == "brute_force":
            # Simulate repeated failed login attempts from the same IP
            ip = random.choice(brute_force_ips)
            url = "/login"
            status = 401  # Unauthorized
            for _ in range(random.randint(10, 15)):
                log_entry = (
                    f"{ip} - - "
                    f"[{datetime.now().strftime('%d/%b/%Y:%H:%M:%S %z')}] "
                    f"\"{method} {url} HTTP/1.1\" "
                    f"{status} {response_size}"
                )
                with open(log_file, "a") as file:
                    file.write(log_entry + "\n")

                # Add some randomness to log generation speed
                time.sleep(random.uniform(0.1, 1.0))

        elif log_type == "ddos":
            # Simulate high request rates from the same IP
            ip = fake.ipv4()
            for _ in range(random.randint(50, 60)):
                log_entry = (
                    f"{ip} - - "
                    f"[{datetime.now().strftime('%d/%b/%Y:%H:%M:%S %z')}] "
                    f"\"{method} {url} HTTP/1.1\" "
                    f"{status} {response_size}"
                )
                with open(log_file, "a") as file:
                    file.write(log_entry + "\n")

                # Add some randomness to log generation speed
                time.sleep(random.uniform(0.1, 0.5))


        elif log_type == "sql_injection":
            # Simulate SQL injection attempts
            url = random.choice(sql_injection_patterns)

        elif log_type == "xss":
            # Simulate XSS attempts
            url = random.choice(xss_patterns)

        # Format the log entry
        log_entry = (
            f"{ip} - - "
            f"[{datetime.now().strftime('%d/%b/%Y:%H:%M:%S %z')}] "
            f"\"{method} {url} HTTP/1.1\" "
            f"{status} {response_size}"
        )

        # Write the log entry to the file
        with open(log_file, "a") as file:
            file.write(log_entry + "\n")

        # Add some randomness to log generation speed
        time.sleep(random.uniform(0.1, 1.0))


# Run the log generator
if __name__ == "__main__":
    pass
