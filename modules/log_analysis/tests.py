from LogAnalysis import LogAnalysis
import threading
from logs.log_generator import generate_logs
import os

if __name__ == "__main__":
    LOG_DIR = "../logs"
    LOG_FILE = f"{LOG_DIR}/apache_logs.log"
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, "w").close()
    log_analyzer = LogAnalysis(log_dir=LOG_DIR, log_file=LOG_FILE)
    try:
        generate_thread = threading.Thread(target=generate_logs, args=(LOG_FILE,))
        log_thread = threading.Thread(target=log_analyzer.run, daemon=True)


        generate_thread.start()
        log_thread.start()

        generate_thread.join()
        log_thread.join()

    except KeyboardInterrupt:
        print("\nExiting...")


