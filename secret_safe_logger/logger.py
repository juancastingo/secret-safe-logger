"""
Convenience factories for creating and configuring secret-safe loggers.
"""

from __future__ import annotations

import logging
import sys
from typing import IO, Pattern, Sequence

from secret_safe_logger.filter import SecretRedactionFilter
from secret_safe_logger.formatter import SafeJsonFormatter, SafeTextFormatter


def get_safe_logger(
    name: str | None = None,
    level: int = logging.INFO,
    structured: bool = False,
    stream: IO[str] | None = None,
    custom_patterns: Sequence[Pattern[str]] | None = None,
) -> logging.Logger:
    """
    Get or create a Logger pre-configured with SecretRedactionFilter
    and appropriate safe formatters.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Avoid duplicate handlers if already configured
    if not logger.handlers:
        handler = logging.StreamHandler(stream or sys.stderr)
        handler.setLevel(level)

        if structured:
            handler.setFormatter(SafeJsonFormatter(custom_patterns=custom_patterns))
        else:
            fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
            handler.setFormatter(SafeTextFormatter(fmt=fmt, custom_patterns=custom_patterns))

        handler.addFilter(SecretRedactionFilter(custom_patterns=custom_patterns))
        logger.addHandler(handler)

    return logger


def configure_root_logger(
    level: int = logging.INFO,
    structured: bool = False,
    custom_patterns: Sequence[Pattern[str]] | None = None,
) -> None:
    """
    Configure the root logger so that all library and application loggers
    automatically benefit from secret redaction.
    """
    root = logging.getLogger()
    root.setLevel(level)

    # Remove existing handlers to avoid duplicates
    for handler in list(root.handlers):
        root.removeHandler(handler)

    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level)

    if structured:
        handler.setFormatter(SafeJsonFormatter(custom_patterns=custom_patterns))
    else:
        fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        handler.setFormatter(SafeTextFormatter(fmt=fmt, custom_patterns=custom_patterns))

    handler.addFilter(SecretRedactionFilter(custom_patterns=custom_patterns))
    root.addHandler(handler)
