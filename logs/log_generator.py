import time
import random
from faker import Faker

# Initialize Faker
fake = Faker()

# Common HTTP methods and response codes
http_methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]
status_codes = [200, 201, 301, 302, 400, 401, 403, 404, 500, 503]


# Log generation function
def generate_apache_log():
    ip_address = fake.ipv4()
    timestamp = fake.date_time_this_year().strftime("%d/%b/%Y:%H:%M:%S %z")
    method = random.choice(http_methods)
    endpoint = fake.uri_path()
    protocol = "HTTP/1.1"
    status_code = random.choice(status_codes)
    bytes_sent = random.randint(200, 5000)

    log_line = (
        f'{ip_address} - - [{timestamp}] "{method} /{endpoint} {protocol}" {status_code} {bytes_sent}'
    )
    return log_line


# Continuously generate logs
def continuous_log_generation():
    while True:
        log = generate_apache_log()
        print(log)
        time.sleep(random.uniform(0.1, 1))  # Simulates a delay between log entries


# Run the log generator
if __name__ == "__main__":
    try:
        continuous_log_generation()
    except KeyboardInterrupt:
        print("\nLog generation stopped.")
