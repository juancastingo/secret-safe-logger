"""
Standard library logging.Filter implementation for transparent secret redaction.
"""

from __future__ import annotations

import logging
from typing import Pattern, Sequence

from secret_safe_logger.patterns import redact_text, sanitize_data


class SecretRedactionFilter(logging.Filter):
    """
    A logging.Filter that intercepts LogRecord instances and redacts
    sensitive information from the message, formatted arguments, and extras.
    """

    def __init__(
        self,
        name: str = "",
        custom_patterns: Sequence[Pattern[str]] | None = None,
    ) -> None:
        super().__init__(name)
        self.custom_patterns = custom_patterns

    def filter(self, record: logging.LogRecord) -> bool:
        # Redact main message string
        if isinstance(record.msg, str):
            record.msg = redact_text(record.msg, self.custom_patterns)
        elif isinstance(record.msg, (dict, list)):
            record.msg = sanitize_data(record.msg, self.custom_patterns)

        # Sanitize arguments if provided
        if record.args:
            if isinstance(record.args, dict):
                record.args = sanitize_data(record.args, self.custom_patterns)
            elif isinstance(record.args, tuple):
                record.args = tuple(sanitize_data(arg, self.custom_patterns) for arg in record.args)

        return True
