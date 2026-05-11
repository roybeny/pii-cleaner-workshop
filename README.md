# PII Cleaner

Production-grade PII (Personally Identifiable Information) detection and redaction service. Synchronous REST API, stateless, designed for air-gapped on-prem deployment, SOC 2 + GDPR aware.

Full product & design spec: [docs/SPEC.md](docs/SPEC.md).

## Features

- `POST /v1/clean` — redact PII in free-form text.
- `POST /v1/clean/records` — clean JSON records with per-field policy.
- Tenant API keys (Argon2id), per-tenant rate limiting, tamper-evident audit log.
- Prometheus metrics, structured JSON logs (PII-blocking processor), optional OpenTelemetry.

## Quickstart (local, 60 seconds)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
python -m spacy download en_core_web_lg

# Hash an API key and drop it into config/tenants.yaml:
python -c "from argon2 import PasswordHasher; print(PasswordHasher().hash('my-dev-key'))"
cp config/tenants.example.yaml /tmp/tenants.yaml   # then paste the hash

PII_TENANTS_FILE=/tmp/tenants.yaml \
  uvicorn pii_cleaner.main:app --reload --port 8000
```

Call it:

```bash
curl -s localhost:8000/v1/clean \
  -H 'Authorization: Bearer my-dev-key' \
  -H 'Content-Type: application/json' \
  -d '{"text":"email john@acme.com"}' | jq
```

OpenAPI UI: <http://localhost:8000/docs>.

## Configuration

All settings are environment variables prefixed `PII_`.

| Variable | Default | Purpose |
|---|---|---|
| `PII_LOG_LEVEL` | `INFO` | Log verbosity. |
| `PII_TENANTS_FILE` | `/etc/pii-cleaner/tenants.yaml` | Tenant registry path. |
| `PII_MAX_TEXT_BYTES` | `1048576` | Max request body for `/v1/clean`. |
| `PII_MAX_RECORDS_BYTES` | `10485760` | Max request body for `/v1/clean/records`. |
| `PII_DEFAULT_RPS` | `100` | Fallback per-tenant rate limit. |
| `PII_DEFAULT_BURST` | `200` | Fallback per-tenant burst. |
| `PII_REQUEST_TIMEOUT_SECONDS` | `10.0` | Hard cap per request. |
| `PII_OTEL_ENABLED` | `false` | Opt-in tracing. |
| `PII_OTEL_ENDPOINT` | — | OTLP gRPC endpoint. |
| `PII_AUDIT_HMAC_KEY_FILE` | — | HMAC key file for audit chain. |

### Tenant registry

See [`config/tenants.example.yaml`](config/tenants.example.yaml). Two active keys per tenant are supported for zero-downtime rotation. Send `SIGHUP` to reload the registry without restart.

## Operations

- **Health**: `GET /health/live` (process), `GET /health/ready` (analyzer loaded).
- **Metrics**: `GET /metrics` (Prometheus).
- **Audit log**: stdout stream named `pii_cleaner.audit`; each line has `prev_hash → hash` HMAC chain.
- **Graceful shutdown**: SIGTERM drains in-flight up to 30 s.

## Development

```bash
pip install -e '.[dev]'
pytest              # unit + integration
ruff check .
black --check .
mypy src
pip-audit           # dep vulnerability scan
```

## Layout

```
src/pii_cleaner/
├── api/              # routes + pydantic schemas
├── auth/             # bearer token + Argon2 verify
├── config/           # pydantic-settings + tenant registry
├── core/             # Presidio wrapper + cleaning orchestration
│   └── recognizers/  # custom recognizer plugins (extension point)
├── observability/    # logging, metrics, tracing, audit
├── ratelimit/        # token bucket
├── errors.py         # typed errors + handlers
└── main.py           # FastAPI app factory
```

## Compliance posture

SOC 2 (Security) and GDPR (processor) obligations are first-class. Not HIPAA-certified, not a PCI CDE. See [docs/SPEC.md §1.8](docs/SPEC.md) for the full list.
