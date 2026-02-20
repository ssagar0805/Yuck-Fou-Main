"""
Structured logging setup for the AI Security Scanner.
"""

import logging
import sys
from app.core.config import settings


def setup_logging() -> logging.Logger:
    """Configure and return the application logger."""
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)

    logging.basicConfig(
        level=log_level,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    # Suppress noisy third-party loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)

    logger = logging.getLogger("ai_security_scanner")
    logger.info("Logging initialised at level: %s", settings.LOG_LEVEL)
    return logger


logger = setup_logging()
