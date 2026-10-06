"""
Formatters for clean text and structured JSON logging with secret sanitization.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Pattern, Sequence

from secret_safe_logger.patterns import redact_text, sanitize_data


class SafeTextFormatter(logging.Formatter):
    """Standard text formatter that ensures formatted output and tracebacks are sanitized."""

    def __init__(
        self,
        fmt: str | None = None,
        datefmt: str | None = None,
        custom_patterns: Sequence[Pattern[str]] | None = None,
    ) -> None:
        super().__init__(fmt=fmt, datefmt=datefmt)
        self.custom_patterns = custom_patterns

    def format(self, record: logging.LogRecord) -> str:
        formatted = super().format(record)
        return redact_text(formatted, self.custom_patterns)


class SafeJsonFormatter(logging.Formatter):
    """
    Structured JSON formatter that serializes log records into single-line
    JSON objects while guaranteeing all fields and extra attributes are sanitized.
    """

    DEFAULT_FIELDS = frozenset(
        [
            "args",
            "asctime",
            "created",
            "exc_info",
            "exc_text",
            "filename",
            "funcName",
            "levelname",
            "levelno",
            "lineno",
            "module",
            "msecs",
            "message",
            "msg",
            "name",
            "pathname",
            "process",
            "processName",
            "relativeCreated",
            "stack_info",
            "thread",
            "threadName",
        ]
    )

    def __init__(
        self,
        custom_patterns: Sequence[Pattern[str]] | None = None,
        include_extra: bool = True,
    ) -> None:
        super().__init__()
        self.custom_patterns = custom_patterns
        self.include_extra = include_extra

    def format(self, record: logging.LogRecord) -> str:
        record.message = record.getMessage()

        log_payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_text(record.message, self.custom_patterns),
        }

        # Include location metadata
        log_payload["caller"] = f"{record.filename}:{record.lineno}"

        # Capture exception tracebacks if present
        if record.exc_info:
            log_payload["exception"] = redact_text(self.formatException(record.exc_info), self.custom_patterns)
        elif record.exc_text:
            log_payload["exception"] = redact_text(record.exc_text, self.custom_patterns)

        # Include custom extra fields
        if self.include_extra:
            extras: dict[str, Any] = {}
            for k, v in record.__dict__.items():
                if k not in self.DEFAULT_FIELDS and not k.startswith("_"):
                    extras[k] = v
            if extras:
                log_payload["extra"] = sanitize_data(extras, self.custom_patterns)

        return json.dumps(log_payload, default=str)
