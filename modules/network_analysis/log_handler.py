from loguru import logger

# Configure Loguru to log to a file with rotation (splits logs after a certain size)
logger.add("network_analysis.log", rotation="5MB", level="INFO", format="{time} | {level} | {message}")

def log_event(message, level="info"):
    """ Logs messages with different levels using Loguru. """
    if level == "debug":
        logger.debug(message)
    elif level == "warning":
        logger.warning(message)
    elif level == "error":
        logger.error(message)
    else:
        logger.info(message)

# Example usage
if __name__ == "__main__":
    log_event("Network analysis module initialized.", "info")
