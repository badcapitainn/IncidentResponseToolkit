from loguru import logger
import sys

# Configure Loguru logger
logger.remove()  # Remove default logger
logger.add("logs/network_analysis.log", rotation="10MB", level="INFO", format="{time} | {level} | {message}")
logger.add(sys.stdout, format="<green>{time}</green> | <level>{level}</level> | <cyan>{message}</cyan>")


def log_info(message):
    logger.info(message)


def log_warning(message):
    logger.warning(message)


def log_error(message):
    logger.error(message)


def log_alert(message):
    logger.critical(f"🚨 ALERT: {message}")
