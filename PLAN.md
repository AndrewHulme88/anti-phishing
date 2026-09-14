# Phishing Email Analyzer MVP Plan

## Product goal

Provide developers with a versioned API that accepts an `.eml` file and returns parsed email data, extracted indicators, explainable phishing findings, and a deterministic risk assessment.

## MVP scope

### Phase 1: Make the parser a reliable API

- [✅] Rename or introduce the endpoint as `POST /v1/analyze`.
- [✅] Define Pydantic response models for message metadata, URLs, attachments, findings, risk, and errors.
- [✅] Return HTTP 400 for invalid or corrupted email files.
- [✅] Validate upload size and reject unsupported input safely.
- [✅] Normalize headers, addresses, dates, body content, URLs, and attachment metadata.
- [✅] Keep raw email content out of responses and logs by default.

### Phase 2: Add deterministic phishing analysis

- [ ] Extract URLs from plain text and HTML, including visible link text and destination.
- [ ] Compare `From`, `Reply-To`, display names, and destination domains.
- [ ] Flag mismatched visible links, IP-address URLs, punycode, URL shorteners, unsafe schemes, and HTTP links.
- [ ] Detect urgency, credential requests, account suspension threats, payment pressure, and requests for sensitive information.
- [ ] Flag risky attachment extensions and suspicious double extensions.
- [ ] Parse SPF, DKIM, DMARC, and `Authentication-Results` headers when available.
- [ ] Emit stable finding codes, severity, title, evidence, and remediation context.
- [ ] Calculate a documented score and map it to `low`, `medium`, or `high` risk.

### Phase 3: Test the security boundary

- [ ] Add tests for normal text email, HTML email, multipart messages, and attachments.
- [ ] Add malformed MIME, missing headers, duplicate headers, encoded headers, and oversized input cases.
- [ ] Add tests for spoofed sender fields, deceptive links, dangerous filenames, and header injection attempts.
- [ ] Verify that analysis is deterministic for the same input.
- [ ] Confirm that attachment contents are never executed or unnecessarily persisted.

### Phase 4: Developer release

- [ ] Add API-key authentication and basic rate limiting.
- [ ] Document request and response examples in OpenAPI and a README.
- [ ] Add structured logging, health checks, and a configurable maximum upload size.
- [ ] Add a small collection of sanitized example emails for local testing.
- [ ] Provide a reproducible install and run command from a clean environment.
- [ ] Publish a versioned API contract and a short security/privacy policy.

## Explicitly out of scope for the first release

- Machine-learning or LLM classification.
- Live URL reputation and DNS lookups.
- Sandbox execution of attachments or URLs.
- User accounts, dashboards, billing, and long-running analysis jobs.
- Persisting uploaded email content by default.

## Release criteria

The MVP is ready when a developer can submit an `.eml` file with one documented request and receive a stable response containing normalized email data, extracted indicators, explainable findings, and a deterministic risk level. Invalid input must produce predictable errors, uploads must be bounded, and the core behavior must be covered by automated tests.
