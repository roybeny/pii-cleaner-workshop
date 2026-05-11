# Workshop Use Cases

A tiered set of exercises for the PII Cleaner codebase. The point of each exercise is **not** the feature — it's what the exercise teaches participants about working with a coding agent. Every exercise is feasible on a single developer machine with no cloud resources, no paid APIs, and no external services beyond what ships in this repo (and, for #6, a locally-run Grafana container).

## How to read this document

Each exercise follows the same template:

- **Goal** — the user-visible outcome.
- **Why this exercise** — the specific agent-collaboration skill it drills.
- **Files to look at** — the likely starting points. Participants are expected to *use the agent to find more*, not to treat this as an exhaustive list.
- **Prompt starter** — a suggested first message to the agent. Copy-paste-friendly, but participants should adapt it.
- **Acceptance criteria** — concrete checks. If all pass, the exercise is done.
- **Stretch** — optional follow-ons for fast finishers.
- **Estimated time** — rough guide for a participant working with an agent.

## Facilitator notes

- Exercises are ordered easiest → hardest within each tier, but tiers are independent — pick one from each tier for a balanced workshop.
- The warm-up tier is **debug-and-extend**: participants don't design anything new, they read existing code and make targeted changes. This is where most agent-collaboration failures show up (over-eager refactors, drive-by edits, scope creep) and it's the best place to coach those habits.
- The medium tier is **one feature, every layer**: the pedagogical sweet spot. Participants must keep the agent coherent across `api/`, `core/`, and tests without losing the thread.
- The harder tier is **design, not just build**: the prompts are deliberately under-specified. The skill being drilled is *pushing back on the agent's first answer* and *getting it to ask clarifying questions*.
- Recommended workshop split if picking three: **#1 (warm-up debug), #4 (MASK action), and #7 or #9 as a stretch.**

---

## Warm-up tier — navigate an unfamiliar codebase

### 1. Fix the phone-detection gap

**Goal.** The request below currently returns the `notes` field unchanged. After the fix, `notes` must be redacted to `"[PHONE_NUMBER]"`.

```bash
curl -s localhost:8000/v1/clean \
  -H 'Authorization: Bearer my-dev-key' \
  -H 'Content-Type: application/json' \
  -d '{"text":"call me at 415-962-8731"}'
```

**Why this exercise.** This is a *real bug*, not a contrived one. The symptom is "phone not redacted" but the cause lives at the intersection of three files (`core/analyzer.py`, `core/cleaner.py`, `config/settings.py`) and requires understanding how Presidio's confidence score interacts with the policy threshold. It's the perfect opener for teaching participants to *trace a symptom to root cause with the agent* rather than accepting the first plausible explanation the agent offers.

**Files to look at.**
- `src/pii_cleaner/core/analyzer.py` — how detection scores come out of Presidio.
- `src/pii_cleaner/core/cleaner.py` — how scores are filtered against the policy threshold.
- `src/pii_cleaner/config/settings.py` — where `default_threshold` lives and how per-type thresholds work.

**Prompt starter.**
> A user reports that `POST /v1/clean` with `"call me at 415-962-8731"` does not redact the phone number, but the same number redacts fine with `"phone: 415-962-8731"`. I'd like you to trace this end-to-end and explain the root cause *before* proposing a fix. Don't change code yet.

**Acceptance criteria.**
- A written root-cause explanation (one paragraph) — the agent should be able to articulate *why* "call me at" fails and "phone:" works.
- The fix is implemented in either the policy layer (per-type threshold) or the recognizer layer (extended context list), not both.
- A new test in `tests/test_cleaner.py` that fails on `master` and passes on the fix branch.
- No unrelated changes. `git diff --stat` should touch ≤3 files.

**Stretch.** Add a facilitator-supplied fuzz corpus of 20 phone formats and verify recall.

**Estimated time.** 30–45 min.

---

### 2. Add a new entity type end-to-end

**Goal.** Add detection for an internal employee ID (`EMP-\d{6}`, e.g. `EMP-123456`) as a first-class entity type. After the change, `POST /v1/clean` with `"ticket from EMP-123456"` must return `"ticket from [EMPLOYEE_ID]"`.

**Why this exercise.** A textbook "tour the codebase" task — every layer needs a small change, and the agent must find them all. The failure mode to coach around is the agent declaring success after updating only the recognizer and missing the schema/default-entities/test surface.

**Files to look at.**
- `src/pii_cleaner/core/recognizers/` — the extension point for custom recognizers.
- `src/pii_cleaner/config/settings.py` — `DEFAULT_ENTITIES`.
- `src/pii_cleaner/core/analyzer.py` — where recognizers get registered.
- `tests/test_cleaner.py` — where to add coverage.

**Prompt starter.**
> I want to add an `EMPLOYEE_ID` entity type that matches the regex `EMP-\d{6}`. Before writing code, map out every file that will need to change and explain why. Then implement and add a test.

**Acceptance criteria.**
- A new recognizer registered via the `core/recognizers/` extension point (not inlined into `analyzer.py`).
- `EMPLOYEE_ID` is recognized by default (appears in `DEFAULT_ENTITIES`).
- A test demonstrating both a positive case (`EMP-123456` → redacted) and a negative case (`EMP-12` → not redacted).
- The OpenAPI docs served at `/docs` show the new entity in example responses or schema descriptions.

**Stretch.** Make the employee-ID regex configurable per tenant via `config/tenants.yaml` instead of hard-coded.

**Estimated time.** 45–60 min.

---

### 3. Rate-limit response headers

**Goal.** Every response must include `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset`. 429 responses must additionally include a `Retry-After` header in seconds.

**Why this exercise.** Small surface area, but the middleware stack (`RateLimit → Auth → Metrics → RequestContext` in `main.py`) is easy to break. Great for teaching participants to *verify ordering and headers* with the agent, not just "does the test pass".

**Files to look at.**
- `src/pii_cleaner/ratelimit/token_bucket.py` — the bucket and the middleware.
- `src/pii_cleaner/main.py` — middleware registration order.
- `tests/test_ratelimit.py` — existing coverage shape.

**Prompt starter.**
> Please add the standard rate-limit response headers to this service. I want `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` on every response, and `Retry-After` on 429s. Show me the planned changes before editing.

**Acceptance criteria.**
- Headers present on 2xx responses from both `/v1/clean` and `/v1/clean/records`.
- `Retry-After` header present (and correct, within ±1s) on 429 responses.
- Existing tests still pass; new tests cover both the happy path and the 429 path.
- No changes to middleware ordering in `main.py`.

**Stretch.** Expose `X-RateLimit-Reset` as a Unix timestamp *and* support clients preferring `Retry-After` as HTTP-date format.

**Estimated time.** 45–60 min.

---

## Medium tier — one feature, every layer

### 4. Add the MASK action

**Goal.** Introduce a second anonymization action alongside REDACT, selectable per entity type in the request policy. REDACT keeps today's behavior (`john@acme.com` → `[EMAIL_ADDRESS]`). MASK produces a length-preserving partial obfuscation (e.g. `john@acme.com` → `j***@***.com`, `415-962-8731` → `***-***-8731`). Participants choose the exact masking rules per entity type and document them.

**Why this exercise.** This is **the** pedagogical sweet spot. The feature is simple enough to fit in one workshop block but cuts through every layer: request schema (`api/schemas.py`), core (`core/cleaner.py`), anonymizer operator config (`core/analyzer.py`), response shape, tests, and OpenAPI examples. It forces participants to *keep the agent on task across many files* without it drifting into "let me also refactor the anonymizer while I'm here."

**Files to look at.**
- `src/pii_cleaner/api/schemas.py` — `PolicyConfig`, request models.
- `src/pii_cleaner/core/policy.py` — policy resolution.
- `src/pii_cleaner/core/cleaner.py` — orchestration.
- `src/pii_cleaner/core/analyzer.py` — the `OperatorConfig` wiring into Presidio's anonymizer.
- `tests/test_cleaner.py` and `tests/test_api.py`.

**Prompt starter.**
> I want to add a `MASK` action alongside the existing REDACT behavior. Callers should be able to specify the action per entity type in the request policy, e.g. `{"actions": {"EMAIL_ADDRESS": "mask", "PERSON": "redact"}}`. Before writing code, propose the request schema change and list every file you expect to touch. I want to review that list before you start editing.

**Acceptance criteria.**
- Default behavior unchanged when no `actions` key is supplied (REDACT for every active entity).
- Per-entity-type MASK works for at least `EMAIL_ADDRESS`, `PHONE_NUMBER`, and `CREDIT_CARD` (other types can fall back to REDACT with a documented note).
- Masking rules documented in `docs/SPEC.md` or a new `docs/ACTIONS.md`.
- Tests cover: REDACT-only, MASK-only, mixed policy, and the default (no `actions`) case.
- `/v1/clean/records` honors the same policy shape.

**Stretch.** Accept a per-entity-type mask character and visible-tail length (e.g. `{"mask": {"char": "#", "visible": 4}}`).

**Estimated time.** 1.5–2 hrs.

---

### 5. Deterministic hash action

**Goal.** Add a HASH action that replaces PII with `sha256(salt || value)[:16]` where the salt is per-tenant and loaded from the tenant registry. Downstream systems can join on the hash without ever seeing the original value.

**Why this exercise.** This is the MASK exercise plus a *security dimension*. The agent will almost certainly produce insecure first-draft code — common failures: logging the salt, including the salt in the audit record, using an unsalted hash, or using a shared default salt. The skill being drilled is *reviewing agent output for security*, not just for correctness.

**Files to look at.**
- `src/pii_cleaner/config/settings.py` — `Tenant` model (add the salt here).
- `config/tenants.example.yaml` — example with salt.
- `src/pii_cleaner/core/analyzer.py` — operator wiring.
- `src/pii_cleaner/observability/audit.py` — **do not** include the salt or the hashed value here beyond type counts.
- `src/pii_cleaner/observability/logging.py` — `FORBIDDEN_LOG_FIELDS` already blocks PII field names; check whether salt or hash need to be added.

**Prompt starter.**
> I want to add a HASH action. Each tenant has a salt in `config/tenants.yaml`; HASHed output is `sha256(salt || value)` truncated to 16 hex chars. Before writing code, list the places where the salt or hashed value must **not** leak (logs, audit records, metrics labels, error messages) and propose how you'll verify that.

**Acceptance criteria.**
- Per-tenant salt configured via `tenants.yaml`; service refuses to start if HASH is requested and no salt is configured.
- Same input + same tenant → same hash (determinism test).
- A negative test verifying that neither the salt nor the hashed value appears in `pii_cleaner.audit` log lines, structured log output, or Prometheus label values.
- Rotating the salt invalidates old hashes (documented, tested).

**Stretch.** Support dual salts (old + new) for a rotation window, mirroring the key-rotation pattern already in the tenant registry.

**Estimated time.** 1.5–2 hrs.

---

### 6. Per-entity latency histograms + local Grafana dashboard

**Goal.** Add a Prometheus histogram `pii_entity_detection_duration_seconds` with a `type` label (per entity type) and produce a `dashboards/pii-cleaner.json` importable into a locally-run Grafana. The facilitator will provide a `docker-compose.observability.yml` that runs Prometheus + Grafana locally and scrapes the service.

**Why this exercise.** Cross-cutting observability work, plus a non-code artifact (JSON dashboard). The skill being drilled is *making the agent produce a file format it doesn't strictly own* (Grafana dashboard JSON) correctly — participants learn to pair the agent with external references ("here's Grafana's dashboard schema, match it exactly").

**Files to look at.**
- `src/pii_cleaner/observability/metrics.py` — existing histogram patterns.
- `src/pii_cleaner/core/cleaner.py` — where to measure per-entity timing.
- `dashboards/` — new directory.

**Prompt starter.**
> I want per-entity-type detection latency exposed as a Prometheus histogram and a committed Grafana dashboard JSON that visualizes it alongside the existing request metrics. Before editing, propose the histogram's buckets and explain why — high-cardinality labels are a real risk here.

**Acceptance criteria.**
- Histogram registered in `observability/metrics.py` with a documented bucket set.
- `type` label cardinality capped to the configured entity types (not unbounded).
- `/metrics` endpoint exposes the new histogram.
- `dashboards/pii-cleaner.json` imports cleanly into Grafana 10+ and shows at least: request rate, p50/p95 request latency, per-entity detection rate, per-entity p95 detection latency.
- `README.md` gains a "Local observability" section with the docker-compose command.

**Stretch.** Add an alerting rule file (`dashboards/alerts.yaml`) for "p95 request latency > 500 ms for 5 min".

**Estimated time.** 1.5–2 hrs.

---

## Harder tier — design, not just build

### 7. Reversible tokenization with a local vault

**Goal.** Add a TOKENIZE action that replaces each PII value with a stable opaque token (e.g. `tok_7f3a…`). The reverse mapping is stored in a local SQLite file. A new endpoint `POST /v1/rehydrate` accepts tokens and returns the original values, gated by an API key scope distinct from the cleaning scope.

**Why this exercise.** Deliberately under-specified. The agent will happily produce an insecure first draft (no scopes, tokens predictable, vault unencrypted, no rate limit on rehydrate). The skill being drilled is **saying "no, redo that" to the agent** and *getting it to ask clarifying questions before writing code*.

**Files to look at.**
- `src/pii_cleaner/auth/` — today's API keys are scope-less; participants must extend them.
- `src/pii_cleaner/config/settings.py` — vault path, token secret.
- `src/pii_cleaner/api/` — new `routes_rehydrate.py`.
- `tests/` — new coverage.

**Prompt starter.**
> I want to add reversible tokenization. Think of at least 5 clarifying questions I should answer before you write any code — around token format, vault location, authentication for rehydrate, rotation, and failure modes. List them and wait for my answers.

**Acceptance criteria.**
- The agent asks clarifying questions before writing code (facilitator verifies).
- Tokens are *unpredictable* (cryptographically random, not sequential) and *stable* (same value → same token within a tenant, documented behavior).
- Rehydrate endpoint requires a key with a distinct scope from the cleaning endpoints; a cleaning-only key gets 403.
- Rehydrate is rate-limited at least as strictly as `/v1/clean`, ideally stricter.
- The SQLite vault file is written with mode 0600; documented in `docs/SPEC.md`.
- End-to-end test: clean → tokenize → rehydrate → assert round-trip.

**Stretch.** Add a TTL to vault entries with a background sweeper.

**Estimated time.** 2.5–3 hrs.

---

### 8. Audit-log verifier CLI

**Goal.** A console command `pii-audit-verify <logfile>` that reads the JSON-lines audit stream produced by the service, recomputes the HMAC chain, and exits non-zero with a clear report on the first tampered record. Requires the HMAC key (same file as `PII_AUDIT_HMAC_KEY_FILE`).

**Why this exercise.** Great defensive-side exercise. The skill being drilled is *making the agent produce a tool whose output format must match an existing format exactly, with no drift*. The agent must *read* `observability/audit.py` carefully rather than *invent* a plausible-looking chain format.

**Files to look at.**
- `src/pii_cleaner/observability/audit.py` — the producer. Verifier must mirror this exactly.
- `pyproject.toml` — `[project.scripts]` for the console entry point.
- `tests/test_audit.py` — extend with verifier tests.

**Prompt starter.**
> Read `src/pii_cleaner/observability/audit.py` carefully and then implement a CLI that verifies an audit log. It must be bit-exact with the producer — no reinvention. Before implementing, describe in one paragraph *exactly* how the producer computes each record's hash, and confirm with me before writing code.

**Acceptance criteria.**
- `pip install -e .` exposes `pii-audit-verify` on `$PATH`.
- Verifier exits 0 on an untampered log, non-zero on a tampered one.
- On failure, output names the offending line number and the expected-vs-actual hash.
- Tests include: clean log, mutated body, deleted record, reordered records, wrong HMAC key. All detected.

**Stretch.** Add a `--since <ISO-timestamp>` flag and a `--json` output mode for CI integration.

**Estimated time.** 2–3 hrs.

---

### 9. Custom recognizer plugin from config (with ReDoS protection)

**Goal.** Load user-supplied regex recognizers from `config/recognizers/*.yaml` at startup (and on SIGHUP). Each file defines one recognizer: entity type name, one or more regex patterns, optional context words, and a default score. The loader must reject patterns that are vulnerable to catastrophic backtracking (ReDoS).

**Why this exercise.** The prompt is deliberately under-specified. "Reject ReDoS-vulnerable patterns" has no single right answer — options include per-pattern execution timeout (using the `regex` library's `timeout` parameter), static analysis of the pattern AST, a conservative whitelist of constructs, or a combination. The skill being drilled is *navigating a genuinely ambiguous design with the agent* and *holding the agent to a security bar* when it proposes a shortcut.

**Files to look at.**
- `src/pii_cleaner/core/recognizers/` — the extension point.
- `src/pii_cleaner/config/settings.py` — SIGHUP reload pattern is already there for tenants; reuse the pattern.

**Prompt starter.**
> I want to load user-supplied regex recognizers from YAML config at startup and on SIGHUP. The hard part is ReDoS protection — patterns like `(a+)+b` on a long input can hang the process. Propose two or three defensive strategies with trade-offs before picking one. Do not write code yet.

**Acceptance criteria.**
- At least one documented defense against ReDoS, explained in the PR description.
- A test that demonstrates a known-vulnerable pattern (e.g. `(a+)+b`) is either rejected at load time or executes within a bounded time on a pathological input.
- SIGHUP reloads the recognizer set without a process restart; a test covers this.
- A malformed YAML file fails loud at startup with a clear error pointing at the offending file and line.

**Stretch.** Support per-recognizer tenant allow-lists so not every tenant gets every custom recognizer.

**Estimated time.** 3 hrs.

---
