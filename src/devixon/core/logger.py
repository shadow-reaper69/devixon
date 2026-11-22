"""
Structured logging with redaction for DEVIXON.
"""

import logging
import sys
import re
from pathlib import Path
from typing import Optional
from rich.logging import RichHandler
from devixon.core.config import DEFAULT_DATA_DIR

LOG_FILE = DEFAULT_DATA_DIR / "devixon.log"

SENSITIVE_PATTERNS = [
    (re.compile(r"(?i)(api[_-]?key|secret|password|bearer|authorization)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{8,})['\"]?"), r"\1: [REDACTED]"),
    (re.compile(r"(?i)(sk-[a-zA-Z0-9]{20,})"), "[REDACTED_API_KEY]"),
]


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            msg = record.msg
            for pattern, repl in SENSITIVE_PATTERNS:
                msg = pattern.sub(repl, msg)
            record.msg = msg
        return True


def setup_logger(name: str = "devixon", level: str = "INFO", verbose: bool = False) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG if verbose else getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()

    # Redacting filter
    redactor = RedactingFilter()

    # Console Rich Handler
    console_handler = RichHandler(rich_tracebacks=True, show_time=False, show_path=verbose)
    console_handler.setLevel(logging.DEBUG if verbose else getattr(logging, level.upper(), logging.INFO))
    console_handler.addFilter(redactor)
    logger.addHandler(console_handler)

    # File Handler
    try:
        DEFAULT_DATA_DIR.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter("[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s")
        file_handler.setFormatter(file_format)
        file_handler.addFilter(redactor)
        logger.addHandler(file_handler)
    except Exception:
        pass

    return logger


logger = setup_logger()
