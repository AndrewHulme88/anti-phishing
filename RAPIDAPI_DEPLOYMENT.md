# RapidAPI deployment guide

## What this mode does

Set `PHISHING_ANALYZER_RAPIDAPI_PROXY_SECRET` to the value RapidAPI assigns for `X-RapidAPI-Proxy-Secret`. The application then rejects every route except `/health` unless that header matches. This prevents callers from using the origin URL to bypass RapidAPI's authentication, quotas, and billing.

When RapidAPI is in front of the service, set `PHISHING_ANALYZER_RATE_LIMIT_ENABLED=false`. RapidAPI applies quota and rate limits per subscribed consumer; the built-in limiter only sees the proxy's source address and is intended for standalone deployments.

## Deploy the container

Build and run locally first:

```bash
docker build -t phishing-email-analyzer .
docker run --rm -p 8000:8000 \
  -e PHISHING_ANALYZER_RAPIDAPI_PROXY_SECRET=local-test-secret \
  -e PHISHING_ANALYZER_RATE_LIMIT_ENABLED=false \
  phishing-email-analyzer
```

Test the origin:

```bash
curl http://127.0.0.1:8000/health
curl -X POST http://127.0.0.1:8000/v1/analyze \
  -H 'X-RapidAPI-Proxy-Secret: local-test-secret' \
  -F 'file=@examples/benign-account-notice.eml;type=message/rfc822'
```

Deploy this container to a host that provides a public HTTPS URL (for example, Cloud Run, Render, Railway, Fly.io, or a container service you operate). Configure these environment variables as deployment secrets:

| Variable | Recommended value |
| --- | --- |
| `PHISHING_ANALYZER_RAPIDAPI_PROXY_SECRET` | The exact proxy secret copied from RapidAPI after creating the API project. |
| `PHISHING_ANALYZER_RATE_LIMIT_ENABLED` | `false` |
| `PHISHING_ANALYZER_MAX_UPLOAD_BYTES` | `10485760` initially (10 MiB) |

Do not set `PHISHING_ANALYZER_API_KEY` for the RapidAPI-only origin. RapidAPI authenticates consumers; the proxy secret authenticates RapidAPI to your origin.

## Configure RapidAPI

1. Create an API project in RapidAPI Studio. Before enabling proxy-secret mode, download the contract with `curl http://127.0.0.1:8000/openapi.json -o openapi.json`, then upload that file to Studio. Do not import the protected origin URL: it correctly rejects requests that do not originate from RapidAPI.
2. In **Hub Listing → Gateway**, point the Runtime at `https://YOUR-ORIGIN`.
3. Copy the `X-RapidAPI-Proxy-Secret` value from the Gateway firewall section into your host's `PHISHING_ANALYZER_RAPIDAPI_PROXY_SECRET` secret, then redeploy.
4. In Gateway logging, disable request bodies, response bodies, request headers, and response headers. Email uploads are sensitive.
5. Set a small BASIC plan rate limit and quota. RapidAPI applies it per subscriber; begin with a private listing or low free quota.
6. Test the endpoint in the RapidAPI playground using `examples/benign-account-notice.eml`. Confirm direct calls to the origin return `401 INVALID_PROXY_SECRET`.
7. Add your support contact, terms URL, privacy-policy URL, pricing, and product description. Then change visibility to public.

## Before each public release

- Run `uv run python -m unittest discover -s tests -v`.
- Confirm `/health` works and `POST /v1/analyze` only succeeds through RapidAPI.
- Check application logs and RapidAPI logging settings never retain message bodies or headers.
- Review rate limits and the maximum upload size against your hosting costs.
