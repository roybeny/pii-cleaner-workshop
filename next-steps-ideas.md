Do not read this for the design step. 
these are ideas that can be used for later use cases - building on this service

* Documents (PDF, DOCX, TXT) - File uploads, extract text, redact, return cleaned file. Adds OCR/parsing complexity.
* Images / audio - OCR on images, transcripts from audio. Significantly larger scope.

  2. [ ] Async batch API
  Submit job, poll for status, download results. For large files and bulk datasets.
  3. [ ] Streaming / SSE
  Token-stream cleaning for LLM output pipelines. Adds complexity around buffering.
  
  2. [ ] Mask (e.g., j***@***.com)
  Partial obfuscation preserving length/shape. Useful for debugging.
  3. [ ] Tokenize (reversible)
  Replace with a token that maps back to original via secure vault. Required for workflows needing rehydration.
  4. [ ] Hash (one-way, deterministic)
  SHA-256 with salt. Lets analytics join records without exposing values.
  
  1. Add a new entity type (e.g., IBAN, IP_ADDRESS, or an internal employee-ID pattern) end-to-end: recognizer + tests + OpenAPI example. Teaches: navigating an unfamiliar
  codebase with an agent, test-first edits. ~45 min.
  2. Add the MASK action alongside REDACT, configurable per entity type in the request. Teaches: feature spanning request schema → core → response. ~1–2 hrs.
  3. Bulk endpoint for JSON/CSV with per-column PII policy. Teaches: designing a new endpoint, streaming, larger agent task. ~2–3 hrs.
  4. Prometheus metrics + per-entity-type counters + latency histograms, plus a Grafana dashboard JSON. Teaches: cross-cutting middleware work. ~1–2 hrs.
  5. Stretch — custom recognizer plugin loaded from config (user-supplied regexes with ReDoS protection). Teaches: extensibility design, security thinking, handling a
  deliberately under-specified task. ~3 hrs.

  Why this split

  - Include the full entity pipeline once, but with one action and a small entity set. Participants immediately see the end-to-end shape, then adding a second action
  (exercise 2) forces them to touch every layer — that's where the pedagogical value is.
  - Don't pre-build MASK/HASH/TOKENIZE. If the scaffold already has three actions, adding a fourth is pattern-matching. With one, adding the second is real design work.
  - Observability stubs, not full observability. Logs + health endpoints exist; metrics don't. Wiring metrics is a great "work with middleware and a new dependency" exercise.
  - Tests scaffolded but not exhaustive. Shows the pattern; leaves gaps to fill so participants practice writing tests with an agent rather than just editing existing ones.
  - CI exists but minimal. Adding a coverage gate, a security scan (pip-audit), or a container scan becomes its own micro-exercise if you want one.

  If this split sounds right, I'll bake it into the PRD as an explicit "MVP vs. Workshop Extensions" section so the document itself serves as both the spec and the exercise
  list. Want me to proceed with the remaining clarifications (scale, auth, compliance) and write it up?

  2. OAuth2 / OIDC (JWT)
     For end-user or SSO-driven access. More moving parts, more to teach.
  3. mTLS
     Service-to-service in trusted networks. No human-facing auth. Fits air-gapped well.
  4. API keys + mTLS (defense in depth)
     Both layers. Realistic for air-gapped production but adds setup friction.
  