from loguru import logger
import os

# Create a directory for log files if it doesn't exist
log_directory = "logs"
if not os.path.exists(log_directory):
    os.makedirs(log_directory)

# Define the log file path
log_file_path = os.path.join(log_directory, "app_guru.log")

# Remove the default logger
logger.remove()

# Define a custom log format
log_format = (
    "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
    "<level>{level: <8}</level> | "
    "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
    "<level>{message}</level>"
)

# Function to initialize the logger
def setup_logger(log_level: str = "INFO"):
    logger.add(
        log_file_path,
        rotation="1 MB",      # Rotate log file when it reaches 1 MB
        retention="7 days",    # Retain logs for 7 days
        compression="zip",     # Compress old log files
        level=log_level,       # Set log level
        format=log_format       # Custom log format
    )

# Example usage
if __name__ == "__main__":
    setup_logger()  # Initialize the logger
    # Simulate log entries
    for i in range(100):  # Adjust the range as needed for testing
        logger.info(f"This is log entry number {i+1}")
