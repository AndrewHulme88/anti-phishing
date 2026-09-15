# API contract: v1

`POST /v1/analyze` accepts multipart form data with a required `file` field containing an `.eml` message. It returns `200 OK` and the `AnalysisResponse` schema published at `/openapi.json`. The endpoint does not accept a raw-message JSON body.

When `PHISHING_ANALYZER_API_KEY` is set, callers must send that value as `X-API-Key`; absent or incorrect keys return `401 INVALID_API_KEY`. Error responses use `{ "detail": { "code": "...", "message": "..." } }`. The endpoint may also return `400`, `413`, `415`, and `429`; their stable error codes are listed in the README and OpenAPI document.

Example successful response (fields may be `null` when absent in the message):

```json
{
  "message": {"subject": "Routine update", "from": "sender@example.com", "recipients": ["analyst@example.net"], "date": null, "reply_to": null},
  "text_body": "See https://status.example.com/current.",
  "html_body": null,
  "urls": [{"visible_text": null, "destination": "https://status.example.com/current"}],
  "attachments": [],
  "authentication": {"spf": null, "dkim": null, "dmarc": null, "results": []},
  "findings": [],
  "risk": {"score": 0, "level": "low"}
}
```

Compatibility policy: additions of optional fields or finding codes may occur within `v1`; existing fields, types, stable error codes, and documented finding codes will not be removed or changed incompatibly. A breaking change will use a new path version.
