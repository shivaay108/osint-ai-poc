import logging
from pathlib import Path

LOGGER_NAME = "osint"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# Diagnostic logger. Silent by default: logs contain investigation targets, so a
# file is only written when the user asks for one (CLI --log-file).
logger = logging.getLogger(LOGGER_NAME)
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.NullHandler())


def enable_file_logging(
    path: str | Path, level: int = logging.DEBUG
) -> logging.Handler:
    """Attach a file handler to the toolkit logger and return it."""
    log_path = Path(path).expanduser()
    log_path.parent.mkdir(parents=True, exist_ok=True)

    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    logger.addHandler(handler)
    return handler
