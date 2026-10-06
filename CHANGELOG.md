# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-10-06

### Added
- Initial release of **secret-safe-logger** for Python.
- Automatic redaction of AWS keys, JWT tokens, Bearer tokens, GitHub tokens, Stripe keys, Slack tokens, private keys, and database passwords.
- `SecretRedactionFilter` standard library logging filter.
- `SafeJsonFormatter` for zero-leakage structured JSON logging.
- `SafeTextFormatter` for standard formatted text output.
- `get_safe_logger` and `configure_root_logger` convenience utilities.
- Recursive data sanitization for nested dictionaries and lists.
- Full test suite with false-positive validations.
