# Phishing Email Analyzer

Analyze `.eml` email files for phishing indicators using deterministic, offline rules. The API parses normalized message data, URLs, attachment metadata, and available SPF/DKIM/DMARC results, then returns explainable findings and a risk score.

## What it checks

- Sender and Reply-To domain mismatches
- Deceptive, unsafe, shortened, IP-address, HTTP, and punycode links
- Urgency, credential requests, payment pressure, account-suspension language, and requests for sensitive information
- Risky attachment extensions and double extensions
- Failed SPF, DKIM, and DMARC results when present in message headers

## What it does not do

- Execute attachments
- Open or visit URLs
- Perform DNS, reputation, or live threat-intelligence lookups
- Persist raw uploaded email content by default
- Use machine learning or LLM classification

## Analyze an email

Send a multipart request with an `.eml` file in the `file` field. Use only messages you are authorised to submit.

```bash
curl --request POST \
  --url 'https://YOUR-RAPIDAPI-HOST/v1/analyze' \
  --header 'x-rapidapi-host: YOUR-RAPIDAPI-HOST' \
  --header 'x-rapidapi-key: YOUR_RAPIDAPI_KEY' \
  --form 'file=@benign-account-notice.eml;type=message/rfc822'
```

The API accepts `.eml` uploads up to 10 MB. Use sanitized sample messages when testing.

## Example response

```json
{
  "message": {
    "subject": "Example account notice",
    "from": "updates@example.com",
    "recipients": ["analyst@example.net"],
    "date": null,
    "reply_to": null
  },
  "urls": [
    {
      "visible_text": null,
      "destination": "https://example.com/account"
    }
  ],
  "attachments": [],
  "authentication": {
    "spf": null,
    "dkim": null,
    "dmarc": null,
    "results": []
  },
  "findings": [],
  "risk": {
    "score": 0,
    "level": "low"
  }
}
```

## Risk scoring

The score is deterministic and additive, capped at 100:

| Finding severity | Points |
| --- | ---: |
| Low | 5 |
| Medium | 12 |
| High | 25 |

Scores below 20 are `low`; 20–49 are `medium`; 50 or greater are `high`.

## Important limitations

This API is an analysis aid, not a guarantee that a message is safe or malicious. Review findings with appropriate security controls and human judgement before acting.

## Privacy and support

Email uploads are processed in memory. The service is designed not to log or intentionally persist raw email content, attachment contents, addresses, headers, or API credentials.

- Privacy policy: https://anti-phishing.fly.dev/privacy
- Terms of service: https://anti-phishing.fly.dev/terms
- Support: moonfallsoftware@outlook.com
