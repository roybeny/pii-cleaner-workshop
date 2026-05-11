# PII Cleaner Service — PRD & Design Document

## Context

This document specifies a **production-grade PII (Personally Identifiable Information) cleaning service**, implemented in Python, that will also serve as the codebase for a developers' workshop on working with coding agents. The service detects and redacts PII in plain text and structured data, exposed via a synchronous REST API. The workshop objective motivates a design that is realistic (not a toy), readable (participants will navigate it), and modular (participants will extend it) — all while meeting the non-functional requirements of a real B2B SaaS component.

This document describes the target design. Workshop exercises extend the implementation toward features that are currently spec'd but not yet built (custom recognizer loading, CSV/Parquet I/O, per-operation tracing spans, HASH/MASK operators, etc.). See [`WORKSHOP-USECASES.md`](WORKSHOP-USECASES.md) for which parts of this spec are exercises rather than merged code.

---

# Part 1 — Product Requirements Document (PRD)

## 1.1 Problem statement

Teams integrating LLMs, analytics pipelines, and log aggregation routinely send free-form text containing PII to systems where it should not land. Ad-hoc regex scrubbing is inconsistent across services, misses entities like names and addresses, and creates compliance risk (GDPR Art. 5 data minimization, SOC 2 CC6.1). A centralized service that applies a single, auditable policy solves this once.

## 1.2 Goals

- Detect and redact PII in text and structured records with a single consistent policy.
- Return a **cleaned payload** and a **detection report** (entity types + spans, not values) suitable for downstream systems.
- Be deployable inside a customer's air-gapped environment with no outbound calls.
- Meet SOC 2 (Security) and GDPR processor obligations out of the box.
- Operate at 50–500 RPS per deployment with sub-200ms p95 latency for short text.

## 1.3 Non-goals

- **No reversibility.** No tokenization, no vault, no re-identification path. (Redact only.)
- **No PCI cardholder data environment.** Card numbers are detected and redacted as a safety net, but the service is explicitly out-of-scope for PCI; contracts prohibit sending raw PAN.
- **No document/image/audio ingestion.** Text and structured records only.
- **No data persistence of request payloads.** The service is stateless beyond config and metrics.
- **No multi-language NER at launch.** English only; additional languages are a future extension.
- **Not an async batch system.** Large files go through the structured endpoint synchronously with size limits; true async/batch is out of scope.

## 1.4 Target users & personas

| Persona | Need | How they use it |
|---|---|---|
| Backend engineer (primary) | Scrub free-text before logging or sending to an LLM | Calls `POST /v1/clean` from their service |
| Data engineer | Clean a batch of records before loading into warehouse | Calls `POST /v1/clean/records` with JSON/CSV |
| Security/compliance officer | Evidence that PII is handled per policy | Reads audit logs; reviews detection reports |
| Platform operator | Runs the service in the customer's infrastructure | Deploys via Docker; monitors via Prometheus |

## 1.5 User stories

- **US-1** As a backend engineer, I submit a chat message and receive the same message with emails, phone numbers, and names replaced by type placeholders, plus a report of what was detected.
- **US-2** As a data engineer, I submit a JSON array of records with a per-field PII policy (which fields to clean) and receive the cleaned array.
- **US-3** As a security officer, I can retrieve an audit log of who called the service, when, from where, and what *types* of entities were detected — without the entity values themselves.
- **US-4** As a tenant admin, I can rotate my API key without service interruption (two active keys during overlap).
- **US-5** As an operator, I receive a Prometheus metric for request rate, latency, and per-entity-type detection counts.
- **US-6** As a tenant, I can configure which entity types are active and which are ignored (allowlist of types).

## 1.6 Functional requirements

### FR-1 Text cleaning (`POST /v1/clean`)
- Accepts a JSON body with `text: string` and optional `policy` override.
- Returns `cleaned_text: string`, `entities: [{type, start, end, score}]` (no values), and `report` summary counts.
- Supported entity types (v1): `EMAIL_ADDRESS`, `PHONE_NUMBER`, `CREDIT_CARD`, `IBAN_CODE`, `IP_ADDRESS`, `URL`, `US_SSN`, `PERSON`, `LOCATION`, `DATE_TIME`, `NRP` (nationality/religious/political).
- Detection confidence threshold configurable per type (default 0.5).
- All detected entities replaced with `[<TYPE>]` (e.g. `[EMAIL_ADDRESS]`).

### FR-2 Structured-record cleaning (`POST /v1/clean/records`)
- Accepts JSON array of objects *or* CSV (via `Content-Type`) *or* Parquet (via binary upload with content-type `application/vnd.apache.parquet`).
- Request includes a `field_policy` mapping: `{field_name: "clean"|"skip"|"drop"}`.
- Unknown fields default to `clean`.
- Returns the same shape as input (JSON array / CSV / Parquet) with cleaning applied and a summary report.

### FR-3 Policy management
- A tenant has a **default policy** stored in config (not a database in v1) specifying: active entity types, per-type confidence thresholds, per-type action (always `REDACT` in v1).
- Per-request `policy` field can override the tenant default within the request scope only.

### FR-4 Authentication
- API key per tenant, passed via `Authorization: Bearer <key>` header.
- Keys stored as Argon2id hashes in a config-mounted secret (not plaintext).
- Two active keys per tenant allowed simultaneously to support rotation.
- Missing/invalid key → 401 with opaque error (no tenant enumeration).

### FR-5 Rate limiting
- Per-tenant token bucket: default 100 RPS, 200 burst. Configurable per tenant.
- 429 response with `Retry-After` header on exceed.

### FR-6 Observability
- Structured JSON logs (request_id, tenant_id, latency, entity type counts — **never entity values or raw input/output**).
- Prometheus metrics at `/metrics` (see §2.9).
- OpenTelemetry tracing on request lifecycle (opt-in via config).

### FR-7 Health & readiness
- `GET /health/live` — liveness (process up).
- `GET /health/ready` — readiness (NER model loaded, config valid).

### FR-8 Documentation
- Auto-generated OpenAPI at `/docs` (Swagger) and `/redoc`.
- README covering local run, config, and a 60-second quickstart.

## 1.7 Non-functional requirements

| NFR | Target |
|---|---|
| **Availability** | 99.9% monthly (single-region, multi-replica) |
| **Latency** p50 (text ≤1KB) | ≤ 50 ms |
| **Latency** p95 (text ≤1KB) | ≤ 200 ms |
| **Latency** p95 (text ≤100KB) | ≤ 2 s |
| **Throughput** | 50–500 RPS per deployment, horizontally scalable |
| **Max request size** | 1 MB text; 10 MB structured payload |
| **Cold start** | ≤ 15 s (spaCy model load) — mitigated by readiness probe |
| **Error budget** | < 0.1% 5xx on valid input |
| **Memory per replica** | ≤ 2 GB steady-state (spaCy `en_core_web_lg` is ~750 MB) |
| **CPU per replica** | ≤ 2 vCPU at target RPS with 2 workers |

## 1.8 Security & compliance requirements

### SOC 2 (Security) controls
- **Access control**: API-key auth, keys hashed at rest (Argon2id), rotation without downtime.
- **Audit logging**: every request logged with tenant, timestamp, source IP, correlation ID, outcome, entity-type counts. Logs are append-only, shipped to customer-side SIEM via stdout/file.
- **Change management**: every merge requires PR review + green CI. Signed container images. SBOM generated per release.
- **Vulnerability management**: `pip-audit` and container scan in CI; fail on High/Critical CVEs.
- **Encryption in transit**: TLS 1.2+ terminated at ingress; service also supports direct TLS for private deploys.
- **Secrets management**: all secrets via env vars or mounted files; never in code, never logged.

### GDPR (processor) controls
- **Data minimization**: request payloads are **never persisted** by the service; buffers are released when the handler returns. Operators are expected to configure the container runtime for no-swap (e.g. `--memory-swappiness=0` on Docker, equivalent settings elsewhere); this is an operator responsibility, not a service default.
- **No outbound telemetry**: air-gapped posture; all metrics/logs stay in the customer's network.
- **Processor DPA-friendly**: documented sub-processors (none, by design), documented retention (zero for payloads, 90 days for structured logs — customer-configurable).
- **Deletion / erasure**: because no payloads are stored, right-to-erasure is trivially satisfied for request data. Audit logs contain no PII values (types only), so they are not subject to erasure of the data subject's personal data beyond standard log rotation.
- **Breach-readiness**: signed, tamper-evident audit logs (HMAC chain) enable 72-hour notification forensics.

### Things we explicitly do NOT claim
- Not HIPAA-certified (may be HIPAA-*ready* with added configuration).
- Not PCI-compliant; not part of a CDE.
- Not a certified GDPR processor until DPA is signed with customer.

## 1.9 Success metrics

| Metric | Target |
|---|---|
| Detection recall on internal labeled eval set | ≥ 0.90 for EMAIL/PHONE/CREDIT_CARD/IBAN; ≥ 0.80 for PERSON/LOCATION |
| Detection precision, same set | ≥ 0.95 for regex-based; ≥ 0.85 for NER-based |
| p95 latency on prod traffic | ≤ 200 ms |
| Weekly 5xx rate | < 0.1% |
| Workshop outcome | Participants complete their assigned extension with a working PR |

## 1.10 Assumptions & constraints

- English-language input only in v1.
- Tenant count per deployment ≤ 100 (keyed via config file, not a DB).
- Air-gapped: no calls to external APIs (including no model downloads at runtime — model baked into image).
- Python 3.12+ runtime.

---

# Part 2 — Design Document

## 2.1 Architecture overview

```
                  ┌──────────────────┐
   Client ──TLS──▶│ Ingress / LB     │
                  │ (NGINX / Envoy)  │
                  └────────┬─────────┘
                           │
                  ┌────────▼─────────┐
                  │ FastAPI app      │  (uvicorn + gunicorn, N replicas)
                  │ ┌──────────────┐ │
                  │ │ Middleware   │ │  auth, rate-limit, request-id, logging
                  │ ├──────────────┤ │
                  │ │ Router       │ │  /v1/clean, /v1/clean/records, /health, /metrics
                  │ ├──────────────┤ │
                  │ │ Cleaner core │ │  Presidio AnalyzerEngine + AnonymizerEngine
                  │ ├──────────────┤ │
                  │ │ Config       │ │  pydantic-settings, tenant registry
                  │ └──────────────┘ │
                  └────────┬─────────┘
                           │ stdout
                  ┌────────▼─────────┐
                  │ Customer logging │  (Fluent Bit / Loki / ELK)
                  │ + Prometheus     │
                  └──────────────────┘
```

Single Python service, stateless, horizontally scalable. No database. Tenant config hot-reloaded from a mounted file (SIGHUP).

## 2.2 Technology choices

| Concern | Choice | Rationale |
|---|---|---|
| Language | Python 3.12 | Ecosystem for NLP/NER; workshop participants likely comfortable. |
| Web framework | **FastAPI** | Type-driven, OpenAPI out of box, async. |
| ASGI server | **uvicorn** behind **gunicorn** | Gunicorn for process supervision, uvicorn workers for ASGI. |
| Validation | **pydantic v2** | Native to FastAPI, fast. |
| Config | **pydantic-settings** | Env + file, typed. |
| Detection | **Microsoft Presidio** (`presidio-analyzer`, `presidio-anonymizer`) | Open-source, extensible, regex + spaCy NER; production-proven. |
| NER model | `en_core_web_lg` (spaCy) | Best accuracy/size tradeoff; baked into image. |
| Logging | **structlog** JSON | Correlation IDs, structured fields. |
| Metrics | **prometheus-client** | De facto standard. |
| Tracing | **opentelemetry-sdk** | Vendor-neutral; opt-in. |
| Auth hashing | **argon2-cffi** | Modern password hashing. |
| Rate limiting | In-process token bucket (per tenant) | No Redis — fits air-gap simplicity for a single-replica-aware algorithm; documented as a v1 trade-off (see §2.15). |
| Parquet | **pyarrow** | Standard for Parquet in Python. |
| Tests | **pytest**, **httpx.AsyncClient** | Standard. |
| Lint/format | **ruff**, **black**, **mypy --strict** | Baseline quality gates. |
| Container | Distroless or Chainguard Python base | Minimize CVE surface. |

## 2.3 Repository layout

```
pii-cleaner/
├── pyproject.toml
├── README.md
├── Dockerfile
├── docker-compose.yml
├── config/
│   └── tenants.example.yaml
├── src/pii_cleaner/
│   ├── __init__.py
│   ├── main.py                    # FastAPI app factory
│   ├── api/
│   │   ├── routes_clean.py
│   │   ├── routes_records.py
│   │   ├── routes_health.py
│   │   └── schemas.py             # pydantic models
│   ├── core/
│   │   ├── cleaner.py             # orchestrates analyzer + anonymizer
│   │   ├── analyzer.py            # Presidio wrapper
│   │   ├── recognizers/           # custom recognizers (extension point)
│   │   └── policy.py              # policy resolution
│   ├── auth/
│   │   ├── middleware.py
│   │   └── keys.py                # Argon2 verify, tenant lookup
│   ├── ratelimit/
│   │   └── token_bucket.py
│   ├── observability/
│   │   ├── logging.py
│   │   ├── metrics.py
│   │   └── tracing.py
│   ├── config/
│   │   └── settings.py            # pydantic-settings
│   └── errors.py                  # typed errors + handlers
└── tests/
    ├── unit/
    ├── integration/
    └── fixtures/
```

## 2.4 API design

### 2.4.1 `POST /v1/clean`

**Request**
```json
{
  "text": "Hi, I'm John Doe, email john@acme.com, phone +1-555-0100.",
  "policy": {
    "entities": ["EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON"],
    "thresholds": {"PERSON": 0.7}
  }
}
```

**Response 200**
```json
{
  "cleaned_text": "Hi, I'm [PERSON], email [EMAIL_ADDRESS], phone [PHONE_NUMBER].",
  "entities": [
    {"type": "PERSON", "start": 8, "end": 16, "score": 0.85},
    {"type": "EMAIL_ADDRESS", "start": 25, "end": 38, "score": 1.0},
    {"type": "PHONE_NUMBER", "start": 47, "end": 58, "score": 0.95}
  ],
  "report": {"PERSON": 1, "EMAIL_ADDRESS": 1, "PHONE_NUMBER": 1},
  "request_id": "01HW..."
}
```

**Notes**: `start`/`end` refer to the **original** text offsets. Values are never returned.

### 2.4.2 `POST /v1/clean/records`

**Request (JSON)**
```json
{
  "records": [{"name": "John Doe", "note": "call me at 555-0100", "id": 42}],
  "field_policy": {
    "name": "clean",
    "note": "clean",
    "id":   "skip"
  }
}
```

**Response 200**
```json
{
  "records": [{"name": "[PERSON]", "note": "call me at [PHONE_NUMBER]", "id": 42}],
  "report": {"PERSON": 1, "PHONE_NUMBER": 1},
  "request_id": "01HW..."
}
```

CSV and Parquet variants accept/return the same content-type as the request.

### 2.4.3 Error model

All errors use a typed envelope:
```json
{
  "error": {
    "code": "INVALID_POLICY",
    "message": "Unknown entity type: FOO",
    "request_id": "01HW..."
  }
}
```

Error codes: `UNAUTHORIZED`, `FORBIDDEN`, `INVALID_POLICY`, `PAYLOAD_TOO_LARGE`, `RATE_LIMITED`, `UNSUPPORTED_MEDIA_TYPE`, `INTERNAL_ERROR`.

## 2.5 Detection engine

- **Presidio `AnalyzerEngine`** initialized once per process (costly init).
- Built-in recognizers enabled for the entity list in §FR-1.
- **Custom recognizers directory** (`core/recognizers/`) — any Python file exposing a `recognizer` symbol is registered at startup. This is the primary extension point.
- Per-entity confidence threshold applied post-detection via the policy layer.
- **Anonymization**: `AnonymizerEngine` with a single `OperatorConfig("replace", {"new_value": f"[{entity_type}]"})` applied to every detected span.
- **Determinism**: given identical input + config, output is deterministic. NER model is loaded at startup; no per-request downloads.

### Concurrency model
- `AnalyzerEngine` is thread-safe for inference; one instance per process.
- Gunicorn runs N worker processes (one analyzer per process) with M async threads per process.
- For CPU-bound spaCy inference, offload to a thread pool via `asyncio.to_thread` to keep the event loop responsive.

## 2.6 Configuration

`pydantic-settings`-driven, env-first with file fallback. Key settings:

| Setting | Env var | Default |
|---|---|---|
| Log level | `PII_LOG_LEVEL` | `INFO` |
| Max request size (text) | `PII_MAX_TEXT_BYTES` | `1048576` |
| Max request size (records) | `PII_MAX_RECORDS_BYTES` | `10485760` |
| Tenant file path | `PII_TENANTS_FILE` | `/etc/pii-cleaner/tenants.yaml` |
| Default rate limit RPS | `PII_DEFAULT_RPS` | `100` |
| Default burst | `PII_DEFAULT_BURST` | `200` |
| Default entity types | `PII_DEFAULT_ENTITIES` | full list from §FR-1 |
| OTel enabled | `PII_OTEL_ENABLED` | `false` |
| OTel endpoint | `PII_OTEL_ENDPOINT` | (unset) |

**tenants.yaml** (mounted secret):
```yaml
tenants:
  - id: acme
    keys:                             # two for rotation
      - hash: "$argon2id$v=19$m=65536,t=3,p=4$..."
      - hash: "$argon2id$v=19$m=65536,t=3,p=4$..."
    rate_limit_rps: 200
    policy:
      entities: [EMAIL_ADDRESS, PHONE_NUMBER, PERSON]
      thresholds: {PERSON: 0.7}
```

Reload on `SIGHUP` (no restart needed for key rotation).

## 2.7 AuthN / AuthZ

1. Extract `Authorization: Bearer <key>`.
2. For each tenant in the registry, attempt Argon2 verify against each active hash. **Use constant-time comparison and iterate all tenants on failure** to avoid timing attacks that leak tenant existence. (In practice: hash the presented key with a known pepper, index by hash prefix, then verify — acceptable leak-to-perf trade-off documented in design review.)
3. Cache verified keys per-process in an LRU (key fingerprint → tenant_id) for the key's lifetime.
4. Inject `tenant_id` into request state for downstream middleware and handlers.
5. Authorization in v1 is coarse: valid key ⇒ full access to cleaning endpoints for that tenant's data (no cross-tenant data exists; the service is stateless).

## 2.8 Rate limiting

- In-process token bucket per tenant (`{tenant_id: (tokens, last_refill_ts)}`).
- Per-replica limit; actual global limit = replica_count × configured_rps. Documented as a v1 simplification.
- On exceed: 429 with `Retry-After: <seconds>`.
- `X-RateLimit-Remaining` header on every response.

## 2.9 Observability

### Logging (structlog JSON to stdout)
Every request emits a single log line with:
```
timestamp, level, event, request_id, tenant_id, method, path,
status, latency_ms, entity_counts (map of type→count), client_ip
```
Payload byte sizes are exposed via the `pii_payload_bytes` histogram rather than per-request log fields.
**Forbidden fields**: `text`, `cleaned_text`, entity values, raw record field values. Enforced by a structlog processor that rewrites known-dangerous keys to `<redacted>`, including inside nested structures.

### Metrics (`/metrics`)
- `pii_requests_total{endpoint, tenant, status}` (counter)
- `pii_request_duration_seconds{endpoint, tenant}` (histogram)
- `pii_entities_detected_total{type, tenant}` (counter) — type only, never value
- `pii_payload_bytes{endpoint, direction}` (histogram)
- `pii_ratelimit_rejections_total{tenant}` (counter)
- `pii_analyzer_errors_total{kind}` (counter)

### Tracing
- OpenTelemetry SDK, OTLP exporter, gated by `PII_OTEL_ENABLED`.
- Spans: `http.request` → `auth.verify` → `policy.resolve` → `analyzer.detect` → `anonymizer.apply`.

## 2.10 Error handling

- Global exception handler translates exceptions → typed error envelope (§2.4.3).
- All unexpected exceptions logged at `ERROR` with stack trace and request_id, **never with payload contents**.
- Client errors (4xx) logged at `INFO`; 5xx at `ERROR`.
- Timeouts: per-request 10 s hard cap via `asyncio.wait_for`; returns 504 with `REQUEST_TIMEOUT`.

## 2.11 Audit logging (SOC 2)

- Separate structlog logger `audit` emits to a dedicated stream/file (via configured handler).
- Every request produces exactly one audit event, regardless of outcome.
- Each event includes an **HMAC-SHA256 chain**: `hmac(prev_hash || event_json)` using a per-deployment key mounted as a secret. The chain is tamper-evident; a gap or mismatch proves log manipulation.
- Retention controlled by the customer's log pipeline (default config suggests 1 year).

## 2.12 Deployment

- **Container image**: multi-stage build. Builder installs deps and `python -m spacy download en_core_web_lg`; runtime uses `python:3.12-slim` with only the app + installed site-packages + model. A hardened/distroless base (Chainguard, Wolfi) is a future-work item.
- **Image is self-contained**: model baked in, no outbound fetches at runtime.
- **SBOM + image signing**: planned (syft + cosign); not yet wired in CI.
- **Runtime**: `docker run` or `docker compose up` with tenants file + HMAC key mounted as read-only volumes. Run multiple replicas behind any reverse proxy / load balancer (nginx, HAProxy, Envoy).
- **Resource targets per container**: request `cpu: 500m, memory: 1Gi`; limit `cpu: 2, memory: 2Gi`.
- **Graceful shutdown**: SIGTERM → stop accepting new requests, drain in-flight within 30 s, exit.

## 2.13 CI/CD

Pipeline stages (GitHub Actions assumed, portable to GitLab):
1. **Lint**: ruff + black --check + mypy --strict
2. **Unit tests**: pytest, coverage ≥ 80% enforced
3. **Integration tests**: spin up app via `httpx.AsyncClient`, run end-to-end scenarios
4. **Security**: `pip-audit`, container scan (Trivy/Grype), fail on High/Critical
5. **Build**: multi-arch container (`linux/amd64`, `linux/arm64`)
6. **SBOM + sign** *(planned, not yet wired)*: syft + cosign
7. **Publish**: to customer-accessible registry (not a public one in air-gap scenarios)

## 2.14 Testing strategy

| Layer | What | Tools |
|---|---|---|
| Unit | Cleaner core, policy resolution, auth, rate limiter | pytest |
| Integration | End-to-end `POST /v1/clean` and `/v1/clean/records` | pytest + httpx.AsyncClient |
| Security | No PII in logs test (submit known PII, assert absent in captured logs) | pytest fixture capturing stdout |
| Property-based *(future)* | Regex recognizers don't produce false positives on known-safe strings | hypothesis |
| Contract *(future)* | OpenAPI schema snapshot test | schemathesis |
| Performance *(future)* | Scenario hitting target RPS; asserts p95 latency | locust / k6 (in CI on tagged runs) |
| Evaluation *(future)* | Detection precision/recall on a curated labeled dataset | custom harness, reports to CI |

## 2.15 Scalability & performance plan

- **Horizontal scaling**: stateless replicas behind a reverse proxy / load balancer; autoscale on CPU via the operator's platform of choice (systemd units, process supervisor, container orchestrator, cloud autoscaling group).
- **Vertical**: 2 vCPU / 2 GB per replica is the sweet spot for spaCy `en_core_web_lg`.
- **Hot path optimizations**:
  - Cache compiled regex at module load.
  - Reuse `AnalyzerEngine` instance per process.
  - Short-circuit analyzer when policy narrows entity list.
- **Known limits**:
  - In-process rate limiting is per-replica; global limits drift by replica count. *Future*: Redis-backed token bucket when a shared store is permitted.
  - Single-process spaCy is GIL-bound; scale via processes, not threads.
  - Structured-endpoint processing is per-record serial; parallelize via a worker pool if benchmarks show headroom.

## 2.16 Risks & mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| spaCy model missing at runtime | Service fails readiness | Bake model into image; readiness probe verifies load |
| Regex ReDoS in custom recognizer | Worker stuck, availability hit | Wrap custom recognizers in timeout; document ReDoS pitfalls; reject patterns that fail a static lint |
| PII leakage via logs | Compliance incident | Structlog processor blocks dangerous keys; test asserts absence |
| Timing attack leaks tenant existence | Minor info leak | Constant-time compare; iterate all candidates |
| Large payload OOM | Replica crash | Hard size limit enforced per endpoint + per-request timeout |
| NER false positives redacting benign text | Data quality hit | Configurable per-type thresholds; detection report lets callers audit |
| NER false negatives missing PII | Compliance hit | Use `en_core_web_lg` not `sm`; combine with regex recognizers; eval set in CI |
| Tenant key compromise | Unauthorized access | Dual-active keys for instant rotation via SIGHUP |
| Audit log tampering | Compliance hit | HMAC chain; periodic external verification |

## 2.17 Rollout plan

1. **Internal alpha**: deployed alongside a single non-critical internal log pipeline; compare before/after samples manually.
2. **Shadow mode**: callers mirror traffic to the service without acting on response; eval precision/recall on real data.
3. **GA**: one-tenant pilot, then open onboarding. SLA attached once ≥ 2 weeks of green error budget.

## 2.18 Open questions / future work

- **Reversible tokenization** (requires a vault; out of v1 scope).
- **Streaming endpoint** for LLM token-stream cleaning.
- **Multi-language NER** (additional spaCy models per language, routing).
- **Async batch API** for large file processing.
- **Managed custom-recognizer UI** (currently file-drop only).
- **Redis-backed global rate limiting**.

---

# Part 3 — Critical files (to be created during implementation)

When implementation starts (after plan approval), the following files will be created in the order listed. This section exists so implementers — human or agent — know the skeleton at a glance.

- `pyproject.toml` — project metadata, pinned deps, tool configs (ruff/black/mypy)
- `src/pii_cleaner/main.py` — FastAPI app factory, middleware registration
- `src/pii_cleaner/config/settings.py` — `Settings` and `TenantRegistry` models
- `src/pii_cleaner/core/analyzer.py` — Presidio wrapper, lifecycle
- `src/pii_cleaner/core/cleaner.py` — orchestration: analyze → anonymize → report
- `src/pii_cleaner/core/policy.py` — tenant default + per-request override resolution
- `src/pii_cleaner/auth/middleware.py` — bearer-token extraction + tenant resolution
- `src/pii_cleaner/auth/keys.py` — Argon2 verify, registry lookup
- `src/pii_cleaner/ratelimit/token_bucket.py` — in-process per-tenant bucket
- `src/pii_cleaner/api/routes_clean.py` — `/v1/clean`
- `src/pii_cleaner/api/routes_records.py` — `/v1/clean/records` (JSON/CSV/Parquet)
- `src/pii_cleaner/api/routes_health.py` — `/health/live`, `/health/ready`
- `src/pii_cleaner/api/schemas.py` — pydantic request/response models
- `src/pii_cleaner/observability/logging.py` — structlog setup, PII filter
- `src/pii_cleaner/observability/metrics.py` — Prometheus collectors
- `src/pii_cleaner/observability/tracing.py` — OTel bootstrap
- `src/pii_cleaner/errors.py` — exception types + global handler
- `tests/unit/test_cleaner.py`, `tests/integration/test_api.py`, fixtures
- `Dockerfile` — multi-stage, model-baked
- `docker-compose.yml` — local runtime reference
- `README.md` — quickstart, config, operations

---

# Part 4 — Verification plan

End-to-end verification once implemented:

1. **Local smoke**: `docker compose up` → `curl -H 'Authorization: Bearer <key>' -d '{"text":"..."}' localhost:8000/v1/clean` returns redacted text.
2. **Unit & integration tests**: `pytest` green, coverage ≥ 80%.
3. **Lint/type gates**: `ruff check`, `black --check`, `mypy --strict` clean.
4. **Security scan**: `pip-audit` clean; Trivy scan of image shows no High/Critical.
5. **PII-in-logs test**: submit text with known PII, capture stdout, grep for PII values — must return zero matches.
6. **Detection eval**: run harness against labeled fixtures; recall/precision meet §1.9 targets.
7. **Load test**: Locust at 200 RPS for 5 min; p95 < 200 ms, error rate < 0.1%.
8. **Rotation drill**: add second key to `tenants.yaml`, SIGHUP, verify both keys accepted; remove first, SIGHUP, verify old rejected — no dropped requests.
9. **Audit log chain**: tamper with one audit line, run chain verifier, expect detected break.
10. **Readiness**: kill spaCy model mid-start; `/health/ready` returns 503; `/health/live` stays 200.
