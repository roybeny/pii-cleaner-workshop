# PII Cleaner

>Can't afford to read? Jump to the [Quickstart](#quickstart) to get a local instance running in a few minutes.


An HTTP service that strips PII from text and structured records before data leaves your boundary — useful for cleaning LLM prompts, analytics events, logs, or pipeline payloads. POST text (or a JSON batch), get back redacted output and a detection report. Detection uses [Microsoft Presidio](https://microsoft.github.io/presidio/) — regex for emails, phones, credit cards, SSNs, and a spaCy NER model for names, locations, and organizations.

Built for production: stateless and air-gap-friendly (no network egress at runtime), multi-tenant API keys with zero-downtime rotation, SOC 2 + GDPR posture, configurable per-tenant and per-request policy, and structured JSON logs + Prometheus metrics.

Full product & design spec: [docs/SPEC.md](docs/SPEC.md).

## About the spaCy model ('en_core_web_lg')

PII detection runs on [Microsoft Presidio](https://microsoft.github.io/presidio/), which pairs regex recognizers (for emails, phone numbers, credit cards, etc.) with a spaCy NER model that catches entities regex cannot — names (`PERSON`), locations, organizations, dates, etc.

We require `en_core_web_lg` specifically:

- **`lg` (~750 MB)** — higher-accuracy word vectors; our recall/precision targets in [SPEC §1.9](docs/SPEC.md) assume this model.
- `md` (~40 MB) — reduced accuracy, especially on `PERSON` and `LOCATION`. Not supported.
- `sm` (~12 MB) — fast but materially worse at NER. Not supported.

The model is a one-time ~750 MB download during setup (`python -m spacy download en_core_web_lg`). In the container image it is **baked in at build time** (see [`Dockerfile`](Dockerfile)) so the running service never reaches out to the network — this is what makes the air-gapped posture possible. The first request after process start triggers model load (cold start ≤ 15 s), which is why `/health/ready` only returns 200 once the model is in memory.

## Features

- `POST /v1/clean` — redact PII in free-form text.
- `POST /v1/clean/records` — clean JSON records with per-field policy.
- Tenant API keys (Argon2id), per-tenant rate limiting, tamper-evident audit log.
- Prometheus metrics, structured JSON logs (PII-blocking processor), optional OpenTelemetry.

## Quickstart

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

Structured records with a per-field policy (`clean` = redact PII, `skip` = pass through untouched, `drop` = remove the field entirely):

```bash
curl -s localhost:8000/v1/clean/records \
  -H 'Authorization: Bearer my-dev-key' \
  -H 'Content-Type: application/json' \
  -d '{
    "records": [
      {"id": "u_123", "name": "Jane Doe", "email": "jane@acme.com", "notes": "mobile 415-962-8731"},
      {"id": "u_456", "name": "John Roe", "email": "john@acme.com", "notes": "n/a"}
    ],
    "field_policy": {
      "id":    "skip",
      "name":  "clean",
      "email": "clean",
      "notes": "clean"
    }
  }' | jq
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
| `PII_DEFAULT_THRESHOLD` | `0.5` | Fallback per-entity confidence threshold. |
| `PII_REQUEST_TIMEOUT_SECONDS` | `10.0` | Hard cap per request. |
| `PII_OTEL_ENABLED` | `false` | Opt-in tracing. |
| `PII_OTEL_ENDPOINT` | — | OTLP gRPC endpoint. |
| `PII_AUDIT_HMAC_KEY_FILE` | — | HMAC key file for audit chain. |
| `PII_REQUIRE_AUDIT_KEY` | `false` | When `true`, service refuses to start without a readable `PII_AUDIT_HMAC_KEY_FILE`. Set in production. |

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
