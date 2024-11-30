import os
import logging
import logging.config

# Environment Variables for Configurations
LOG_LEVEL = os.getenv("LOG_LEVEL", "DEBUG")
LOG_FILE_PATH = os.getenv("LOG_FILE_PATH", "app.log")

LOG_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        },
        "detailed": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s - [%(filename)s:%(lineno)d]"
        },
    },
    "handlers": {
        "console": {
            "level": LOG_LEVEL,
            "class": "logging.StreamHandler",
            "formatter": "standard",
        },
        "file": {
            "level": LOG_LEVEL,
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "detailed",
            "filename": LOG_FILE_PATH,
            "maxBytes": 10485760,  # 10 MB per log file
            "backupCount": 5,  # Keep 5 backups
        },
    },
    "loggers": {
        "uvicorn": {
            "handlers": ["console", "file"],
            "level": "INFO",
            "propagate": False,
        },
        "uvicorn.error": {
            "handlers": ["console", "file"],
            "level": "INFO",
            "propagate": False,
        },
        "uvicorn.access": {
            "handlers": ["console", "file"],
            "level": "INFO",
            "propagate": False,
        },
        "myapp": {
            "handlers": ["console", "file"],
            "level": LOG_LEVEL,
            "propagate": False,
        },
    },
}

# Configure logging
logging.config.dictConfig(LOG_CONFIG)
logger = logging.getLogger("myapp")


def get_logger(name: str) -> logging.Logger:
    """
    Create and return a logger with the given name.

    Args:
        name (str): Name of the logger to create.

    Returns:
        logging.Logger: Configured logger instance.
    """
    return logging.getLogger(name)
