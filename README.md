# Phishing Email Analyzer

A versioned FastAPI service that accepts an `.eml` email file and returns normalized message metadata, indicators, explainable deterministic phishing findings, authentication results, and a risk assessment.

## Requirements

- Python 3.12 or newer
- [uv](https://docs.astral.sh/uv/)

## Setup

From the repository root, install the locked dependencies:

```bash
uv sync
uv run fastapi run main.py
```

## Run the API

For development with reload, run:

```bash
uv run fastapi dev main.py
```

The API is then available at `http://127.0.0.1:8000`. Interactive OpenAPI documentation is available at `http://127.0.0.1:8000/docs`.

## Analyze an email

With the server running, submit the included sample email:

```bash
curl -X POST http://127.0.0.1:8000/v1/analyze \
  -F "file=@sample-email.eml;type=message/rfc822"
```

To exercise the phishing-analysis rules, submit the sanitized suspicious sample:

```bash
curl -X POST http://127.0.0.1:8000/v1/analyze \
  -F "file=@sample-phishing-email.eml;type=message/rfc822"
```

The endpoint accepts `.eml` files up to 10 MB by default. Set `PHISHING_ANALYZER_MAX_UPLOAD_BYTES` to a positive byte limit for a deployment.

## Deployment controls

The API is deliberately open by default for local use. To require an API key, set `PHISHING_ANALYZER_API_KEY` before starting the service. Clients then send it in `X-API-Key`:

```bash
PHISHING_ANALYZER_API_KEY=replace-with-a-secret uv run fastapi run main.py
curl -X POST http://127.0.0.1:8000/v1/analyze \
  -H 'X-API-Key: replace-with-a-secret' \
  -F 'file=@examples/benign-account-notice.eml;type=message/rfc822'
```

The process-local rate limiter allows 60 analysis requests per client IP per 60 seconds by default. Configure it with `PHISHING_ANALYZER_RATE_LIMIT_REQUESTS` and `PHISHING_ANALYZER_RATE_LIMIT_WINDOW_SECONDS`. For multiple application workers, place a shared rate limiter or API gateway in front of the service.

For a public RapidAPI listing, use the production container and gateway-only mode in [RAPIDAPI_DEPLOYMENT.md](RAPIDAPI_DEPLOYMENT.md). It validates RapidAPI's proxy secret at the origin and disables the unsuitable per-proxy in-process limiter.

The ready-to-paste marketplace description is in [RAPIDAPI_README.md](RAPIDAPI_README.md).

### Endpoints

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/health` | Returns status, API version, and whether API-key authentication is enabled. |
| `POST` | `/v1/analyze` | Parses a multipart-uploaded `.eml` file. |

`POST /v1/analyze` can return these input errors:

| Status | Code | Meaning |
| --- | --- | --- |
| `400` | `EMPTY_FILE` | The uploaded file has no content. |
| `400` | `INVALID_EMAIL` | The file is not a parseable email message. |
| `413` | `FILE_TOO_LARGE` | The email is larger than 10 MB. |
| `415` | `UNSUPPORTED_FILE_TYPE` | The upload is not named with an `.eml` extension. |
| `401` | `INVALID_API_KEY` | A required API key is absent or incorrect. |
| `429` | `RATE_LIMITED` | The process-local request limit was exceeded. |

The OpenAPI contract is available at `/openapi.json`, with interactive documentation at `/docs`. The current contract is versioned as `v1`; see [API_CONTRACT.md](API_CONTRACT.md) for compatibility commitments and an example response.

## Sanitized examples

The `examples/` directory contains safe local-test messages only: a benign account notice and a phishing-shaped message. They use documentation domains and inert attachment text; no example attachment is executable.

## Run tests

Run the API tests with the project virtual environment:

```bash
.venv/bin/python -m unittest discover -s tests -v
```

Or, after running `uv sync`, use uv directly:

```bash
uv run python -m unittest discover -s tests -v
```

## Privacy and safety

Uploaded email bytes are parsed in memory and are not included in API responses or application logs. Structured logs record only request method, route, status, and duration. The service does not execute attachments or visit extracted URLs. See [SECURITY.md](SECURITY.md) for the release security and privacy policy.

The deployed API also publishes its [privacy policy](/privacy) and [terms of service](/terms). For the Fly deployment, these are available at `https://anti-phishing.fly.dev/privacy` and `https://anti-phishing.fly.dev/terms`.

## Deterministic analysis

The service performs no network lookups. It flags sender/Reply-To mismatches, deceptive or unsafe links, common social-engineering language, risky attachment names, and failed SPF, DKIM, or DMARC results reported in `Authentication-Results`. Each finding has a stable code, severity, evidence, and remediation.

Risk is additive and capped at 100: low-severity findings add 5 points, medium add 12, and high add 25. Scores below 20 are `low`, 20–49 are `medium`, and 50 or greater are `high`.
