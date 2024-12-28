from services import analyze_logs


if __name__ == "__main__":
    log_file = "../logs/apache_logs.log"  # Path to your log file
    alerts = analyze_logs(log_file)

    print("Alerts Generated:")
    for alert in alerts:
        print(alert)
