# 🔒 secret-safe-logger

[![CI](https://github.com/juancastingo/secret-safe-logger/actions/workflows/ci.yml/badge.svg)](https://github.com/juancastingo/secret-safe-logger/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/secret-safe-logger.svg)](https://pypi.org/project/secret-safe-logger/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python Versions](https://img.shields.io/pypi/pyversions/secret-safe-logger.svg)](https://pypi.org/project/secret-safe-logger/)

**secret-safe-logger** is a transparent, high-performance Python logging utility that automatically detects and redacts credentials, JWTs, API keys, and sensitive data from your application logs before they are emitted to disk, stdout, or third-party log aggregators (Datadog, CloudWatch, Sentry, Grafana Loki).

Works seamlessly with standard library `logging`, `structlog`, Django, FastAPI, and Flask.

---

## 📸 Preview

```python
import logging
from secret_safe_logger import get_safe_logger

logger = get_safe_logger("my_app")

# Any accidentally logged secrets are automatically redacted:
logger.info("Initializing client with AWS key AKIAIOSFODNN7EXAMPLE")
# Output:
# 2026-10-06 12:00:00 [INFO] my_app: Initializing client with AWS key AK...[REDACTED]

logger.info("Database connected: postgres://user:SuperSecretPassword123@db.prod:5432/main")
# Output:
# 2026-10-06 12:00:00 [INFO] my_app: Database connected: postgres://user:[REDACTED]@db.prod:5432/main
```

---

## ✨ Features

- **Transparent Integration**: Plugs into standard library `logging.Filter` and `logging.Formatter` with 1 line of configuration.
- **Built-in Token Detection**:
  - AWS Access Key IDs (`AKIA...`)
  - JSON Web Tokens (`eyJ...`)
  - HTTP `Bearer` Authorization tokens
  - GitHub personal access tokens (`ghp_...`, `github_pat_...`)
  - Stripe secret API keys (`sk_live_...`)
  - Slack Bot & User tokens (`xoxb-...`, `xoxp-...`)
  - Database connection string passwords (`postgres://`, `mysql://`, `mongodb://`)
  - Private key blocks (`-----BEGIN ... PRIVATE KEY-----`)
- **Structured JSON Logging**: Includes `SafeJsonFormatter` for zero-leakage production JSON logging with extra fields sanitization.
- **Data Structure Sanitizer**: Recursive sanitization for dictionaries, lists, and kwargs.
- **Extremely Low Overhead**: Pre-compiled regular expressions and fast-path heuristics ensure microsecond performance.
- **Zero Third-Party Dependencies**: Built strictly on the Python Standard Library.

---

## 🚀 Installation

```bash
pip install secret-safe-logger
# or
uv add secret-safe-logger
# or
poetry add secret-safe-logger
```

---

## 📖 Usage Examples

### 1. Ready-to-use Safe Logger
```python
from secret_safe_logger import get_safe_logger

logger = get_safe_logger("app")
logger.info("User login with token: %s", "ghp_1234567890abcdefghijklmnopqrstuvwxyz")
```

### 2. Application-Wide Protection (Configure Root Logger)
Protect every logger in your application (including third-party libraries like `requests`, `urllib3`, `boto3`):
```python
import logging
from secret_safe_logger import configure_root_logger

# Run once during application bootstrap (e.g. main.py or settings.py)
configure_root_logger(level=logging.INFO)

# Now standard logging is safe:
logging.getLogger("boto3").info("Invoked with key AKIAIOSFODNN7EXAMPLE")
```

### 3. Structured JSON Logging for Containers & Cloud
```python
from secret_safe_logger import get_safe_logger

logger = get_safe_logger("api", structured=True)
logger.info("Payment webhook received", extra={"stripe_key": "sk_live_1234567890abcdef", "amount": 5000})

# Emits JSON:
# {"timestamp": "2026-10-06T12:00:00+00:00", "level": "INFO", "logger": "api", "message": "Payment webhook received", "caller": "main.py:10", "extra": {"stripe_key": "[REDACTED]", "amount": 5000}}
```

### 4. Custom Secret Patterns
```python
import re
from secret_safe_logger import get_safe_logger

CUSTOM_TOKEN_RE = re.compile(r"\bmycompany_token_[a-f0-9]{32}\b")

logger = get_safe_logger("custom", custom_patterns=[CUSTOM_TOKEN_RE])
logger.info("Token: mycompany_token_abcdef0123456789abcdef0123456789")
# Output: Token: [REDACTED]
```

---

## 🧪 Running Tests

```bash
python3 -m pytest
```

---

## 📄 License

MIT © [Juan Castiñeira](https://github.com/juancastingo)
