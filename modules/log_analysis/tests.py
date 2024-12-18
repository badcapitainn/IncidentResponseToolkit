from services import analyze_logs

if __name__ == "__main__":
    # use absolute path
    log_file_path = "C:\\Users\\madza\\PycharmProjects\\IncidentResponseToolkit\\logs\\test_logs.json"
    alerts = analyze_logs(log_file_path)
    print("Alerts Generated:")
    for alert in alerts:
        print(alert)
