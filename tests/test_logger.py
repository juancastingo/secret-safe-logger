import io
import json
import logging
import pytest

from secret_safe_logger import (
    SafeJsonFormatter,
    SafeTextFormatter,
    SecretRedactionFilter,
    get_safe_logger,
    redact_text,
    sanitize_data,
)


def test_redact_aws_and_jwt_tokens():
    raw = "Connecting with AWS key AKIAIOSFODNN7EXAMPLE and user token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSignature"
    redacted = redact_text(raw)
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "doNotLeakThisSignature" not in redacted
    assert "[REDACTED]" in redacted


def test_redact_bearer_and_stripe_key():
    fake_stripe = "sk_" + "test_" + "dummysecretkey12345678901234"
    raw = f"Header Authorization: Bearer secret_bearer_token_1234567890 and key {fake_stripe}"
    redacted = redact_text(raw)
    assert "secret_bearer_token_1234567890" not in redacted
    assert fake_stripe not in redacted


def test_redact_database_uri_passwords():
    raw = "Connecting to database postgres://app_user:p@ssw0rd123!@db.internal.corp:5432/production_db"
    redacted = redact_text(raw)
    assert "p@ssw0rd123!" not in redacted
    assert "postgres://app_user:[REDACTED]@db.internal.corp:5432/production_db" in redacted


def test_false_positives_not_redacted():
    normal_text = "User visited https://api.github.com/v1/repos with commit 7b1c4e2a90f845d1234567890abcdef123456789 and UUID 123e4567-e89b-12d3-a456-426614174000"
    redacted = redact_text(normal_text)
    assert redacted == normal_text


def test_sanitize_data_nested_dict():
    payload = {
        "user": "alice",
        "api_key": "secret_key_12345",
        "nested": {
            "password": "my_password",
            "debug": False,
        },
        "tags": ["prod", "us-east-1"],
    }
    sanitized = sanitize_data(payload)
    assert sanitized["user"] == "alice"
    assert sanitized["api_key"] == "[REDACTED]"
    assert sanitized["nested"]["password"] == "[REDACTED]"
    assert sanitized["nested"]["debug"] is False


def test_logger_integration_text_output():
    stream = io.StringIO()
    logger = get_safe_logger("test.text", stream=stream)

    fake_token = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"
    logger.info("Service initialized with token %s and password %s", fake_token, "hunter2")
    output = stream.getvalue()

    assert "1234567890abcdefghijklmnopqrstuvwxyz" not in output


def test_logger_structured_json_output():
    stream = io.StringIO()
    logger = get_safe_logger("test.json", structured=True, stream=stream)

    fake_key = "sk_" + "test_" + "1234567890abcdefghij"
    logger.info(
        "Payment processed",
        extra={"stripe_key": fake_key, "amount": 100},
    )
    output = stream.getvalue().strip()
    data = json.loads(output)

    assert data["message"] == "Payment processed"
    assert data["level"] == "INFO"
    assert data["extra"]["amount"] == 100
    assert data["extra"]["stripe_key"] == "[REDACTED]"
