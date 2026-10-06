"""
Secret detection regex patterns and redaction routines.
"""

from __future__ import annotations

import re
from typing import Any, Mapping, Pattern, Sequence

# High-confidence secret regex patterns
DEFAULT_SECRET_PATTERNS: list[tuple[str, Pattern[str]]] = [
    (
        "AWS_KEY",
        re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    ),
    (
        "JWT",
        re.compile(r"\b(ey[A-Za-z0-9-_=]+\.ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+)\b"),
    ),
    (
        "BEARER_TOKEN",
        re.compile(r"(?i)\bBearer\s+([A-Za-z0-9\-_\.~+/]{12,}=*)\b"),
    ),
    (
        "GITHUB_TOKEN",
        re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{40,255})\b"),
    ),
    (
        "STRIPE_KEY",
        re.compile(r"\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{14,})\b"),
    ),
    (
        "SLACK_TOKEN",
        re.compile(r"\b(xox[baprs]-[0-9]{9,13}-[0-9]{9,13}[a-zA-Z0-9-]*)\b"),
    ),
    (
        "PRIVATE_KEY",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    (
        "URI_PASSWORD",
        re.compile(r"(?i)\b([a-z0-9+.-]+://[^:\s]+:)(.+?)(@(?:[a-zA-Z0-9_.-]+|\[[0-9a-fA-F:]+\])(?::\d+)?(?:/|$|\s))"),
    ),
]

SENSITIVE_KEY_NAMES: frozenset[str] = frozenset(
    [
        "secret",
        "password",
        "passwd",
        "pwd",
        "token",
        "api_key",
        "apikey",
        "auth",
        "authorization",
        "private_key",
        "credential",
        "credentials",
        "client_secret",
        "access_token",
        "refresh_token",
        "session_id",
        "jwt",
        "stripe_key",
        "secret_key",
    ]
)

REDACTED_MASK = "[REDACTED]"


def mask_secret_match(secret: str) -> str:
    """Mask a secret string preserving only a 2-char prefix if sufficiently long."""
    if len(secret) <= 6:
        return REDACTED_MASK
    return f"{secret[:2]}...{REDACTED_MASK}"


def redact_text(
    text: str,
    custom_patterns: Sequence[Pattern[str]] | None = None,
) -> str:
    """Scan and redact any credentials or high-entropy tokens found within text."""
    if not text:
        return text

    redacted = text

    # Apply default patterns
    for name, pattern in DEFAULT_SECRET_PATTERNS:
        if name == "URI_PASSWORD":
            redacted = pattern.sub(rf"\1{REDACTED_MASK}\3", redacted)
        elif name == "BEARER_TOKEN":
            redacted = pattern.sub(rf"Bearer {REDACTED_MASK}", redacted)
        elif name == "PRIVATE_KEY":
            redacted = pattern.sub(f"-----BEGIN PRIVATE KEY----- {REDACTED_MASK} -----END PRIVATE KEY-----", redacted)
        else:
            redacted = pattern.sub(lambda m: mask_secret_match(m.group(0)), redacted)

    # Apply user-supplied custom patterns
    if custom_patterns:
        for pat in custom_patterns:
            redacted = pat.sub(REDACTED_MASK, redacted)

    return redacted


def is_sensitive_key(key: str) -> bool:
    """Check if a dictionary key name suggests sensitive content."""
    clean_key = key.lower().replace("-", "_")
    if clean_key.endswith("_key") or clean_key.startswith("key_"):
        return True
    return any(sens in clean_key for sens in SENSITIVE_KEY_NAMES)


def sanitize_data(
    data: Any,
    custom_patterns: Sequence[Pattern[str]] | None = None,
) -> Any:
    """
    Recursively sanitize data structures (dicts, lists, primitives),
    redacting sensitive keys and values.
    """
    if isinstance(data, str):
        return redact_text(data, custom_patterns)

    if isinstance(data, Mapping):
        sanitized_dict: dict[str, Any] = {}
        for k, v in data.items():
            k_str = str(k)
            if is_sensitive_key(k_str):
                sanitized_dict[k_str] = REDACTED_MASK
            else:
                sanitized_dict[k_str] = sanitize_data(v, custom_patterns)
        return sanitized_dict

    if isinstance(data, (list, tuple, set)):
        items = [sanitize_data(item, custom_patterns) for item in data]
        if isinstance(data, tuple):
            return tuple(items)
        if isinstance(data, set):
            return set(items)
        return items

    return data
