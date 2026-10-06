"""
secret-safe-logger - Automatic secret detection and redaction for Python logging.
"""

from secret_safe_logger.filter import SecretRedactionFilter
from secret_safe_logger.formatter import SafeJsonFormatter, SafeTextFormatter
from secret_safe_logger.logger import configure_root_logger, get_safe_logger
from secret_safe_logger.patterns import is_sensitive_key, redact_text, sanitize_data

__version__ = "0.1.0"

__all__ = [
    "SecretRedactionFilter",
    "SafeJsonFormatter",
    "SafeTextFormatter",
    "get_safe_logger",
    "configure_root_logger",
    "redact_text",
    "sanitize_data",
    "is_sensitive_key",
]
