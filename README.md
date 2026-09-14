# Phishing Email Analyzer

A FastAPI service that accepts an `.eml` email file and returns normalized message metadata, indicators, explainable deterministic phishing findings, authentication results, and a risk assessment.

## Requirements

- Python 3.12 or newer
- [uv](https://docs.astral.sh/uv/)

## Setup

From the repository root, install the locked dependencies:

```bash
uv sync
```

## Run the API

Start the development server:

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

The endpoint accepts `.eml` files up to 10 MB.

### Endpoints

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/health` | Returns `{"status":"ok"}` when the service is running. |
| `POST` | `/v1/analyze` | Parses a multipart-uploaded `.eml` file. |

`POST /v1/analyze` can return these input errors:

| Status | Code | Meaning |
| --- | --- | --- |
| `400` | `EMPTY_FILE` | The uploaded file has no content. |
| `400` | `INVALID_EMAIL` | The file is not a parseable email message. |
| `413` | `FILE_TOO_LARGE` | The email is larger than 10 MB. |
| `415` | `UNSUPPORTED_FILE_TYPE` | The upload is not named with an `.eml` extension. |

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

Uploaded email bytes are parsed in memory and are not included in API responses or application logs. The service does not execute attachments or visit extracted URLs.

## Deterministic analysis

The service performs no network lookups. It flags sender/Reply-To mismatches, deceptive or unsafe links, common social-engineering language, risky attachment names, and failed SPF, DKIM, or DMARC results reported in `Authentication-Results`. Each finding has a stable code, severity, evidence, and remediation.

Risk is additive and capped at 100: low-severity findings add 5 points, medium add 12, and high add 25. Scores below 20 are `low`, 20–49 are `medium`, and 50 or greater are `high`.
