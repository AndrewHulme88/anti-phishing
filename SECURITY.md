# Security and privacy policy

The service parses uploads in memory and does not persist raw messages, attachments, or extracted URL content. It never executes attachments, follows links, performs DNS queries, or calls reputation services.

Responses contain only normalized metadata, bodies, indicators, and analysis findings defined by the API contract. Application logs are structured operational records containing method, route, status, and duration; they intentionally omit email content, filenames, headers, addresses, API keys, and request bodies.

API-key authentication is enabled by setting `PHISHING_ANALYZER_API_KEY`. Use a high-entropy secret supplied by your deployment secret manager, TLS in transit, and an API gateway/shared rate limiter for multi-process or public deployments. The included in-memory limiter is a basic single-process safeguard, not a distributed abuse-prevention system.
