import asyncio
import base64
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

from app.api import RateLimiter, app
from app.config import Settings


class AnalyzeEndpointTests(unittest.TestCase):
    def request(self, filename: str, content: bytes, headers: dict[str, str] | None = None) -> httpx.Response:
        async def send_request() -> httpx.Response:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                return await client.post(
                    "/v1/analyze",
                    files={"file": (filename, content, "message/rfc822")},
                    headers=headers,
                )

        return asyncio.run(send_request())

    def test_normalizes_sample_email_into_the_api_contract(self) -> None:
        response = self.request("sample-email.eml", Path("sample-email.eml").read_bytes())

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["message"]["from"], "security@example.com")
        self.assertEqual(payload["message"]["date"], "2026-09-11T10:30:00+00:00")
        self.assertEqual(payload["attachments"][0]["size"], 38)
        self.assertEqual(
            payload["urls"],
            [
                {"visible_text": None, "destination": "https://example.com/account/activity"},
                {"visible_text": "Review the activity", "destination": "https://example.com/account/activity"},
            ],
        )
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["risk"], {"score": 0, "level": "low"})

    def test_analyzes_a_normal_plain_text_email(self) -> None:
        response = self.request(
            "plain.eml",
            b"From: sender@example.com\r\n"
            b"To: analyst@example.net\r\n"
            b"Subject: Routine update\r\n"
            b"\r\n"
            b"The status page is https://status.example.com/current.\r\n",
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["text_body"].strip(), "The status page is https://status.example.com/current.")
        self.assertIsNone(payload["html_body"])
        self.assertEqual(payload["urls"], [{"visible_text": None, "destination": "https://status.example.com/current"}])
        self.assertEqual(payload["findings"], [])

    def test_extracts_html_link_destination_and_visible_text(self) -> None:
        response = self.request(
            "html.eml",
            b"From: sender@example.com\r\n"
            b"To: analyst@example.net\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n"
            b"\r\n"
            b"<p><a href=\"https://destination.example/reset\">portal.example</a></p>",
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(
            payload["urls"],
            [{"visible_text": "portal.example", "destination": "https://destination.example/reset"}],
        )
        self.assertIn("URL_VISIBLE_TEXT_MISMATCH", {item["code"] for item in payload["findings"]})

    def test_reports_attachment_metadata_without_attachment_content(self) -> None:
        attachment_content = b"this attachment must remain inert"
        encoded_attachment = base64.b64encode(attachment_content)
        response = self.request(
            "attachment.eml",
            b"From: sender@example.com\r\n"
            b"To: analyst@example.net\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=boundary\r\n"
            b"\r\n"
            b"--boundary\r\nContent-Type: text/plain\r\n\r\nHello\r\n"
            b"--boundary\r\n"
            b"Content-Type: application/octet-stream; name=report.txt\r\n"
            b"Content-Disposition: attachment; filename=report.txt\r\n"
            b"Content-Transfer-Encoding: base64\r\n\r\n"
            + encoded_attachment
            + b"\r\n--boundary--\r\n",
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["attachments"], [{"filename": "report.txt", "content_type": "application/octet-stream", "size": len(attachment_content)}])
        self.assertNotIn(attachment_content.decode(), response.text)

    def test_accepts_missing_optional_headers(self) -> None:
        response = self.request("minimal.eml", b"To: analyst@example.net\r\n\r\nHello")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["message"], {"subject": None, "from": None, "recipients": ["analyst@example.net"], "date": None, "reply_to": None})

    def test_handles_duplicate_and_encoded_headers_deterministically(self) -> None:
        response = self.request(
            "headers.eml",
            b"From: =?utf-8?b?Sm9zw6kgVXNlcg==?= <jose@example.com>\r\n"
            b"From: second@example.com\r\n"
            b"To: first@example.com\r\n"
            b"To: second@example.com\r\n"
            b"Subject: =?utf-8?q?Urgent_=E2=9A=A0=EF=B8=8F?=\r\n"
            b"Subject: ignored\r\n\r\nHello",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["message"], {"subject": "Urgent ⚠️", "from": "José User <jose@example.com>", "recipients": ["first@example.com", "second@example.com"], "date": None, "reply_to": None})

    def test_rejects_malformed_multipart_mime(self) -> None:
        response = self.request(
            "truncated.eml",
            b"From: sender@example.com\r\nTo: analyst@example.net\r\n"
            b"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=broken\r\n\r\n"
            b"--broken\r\nContent-Type: text/plain\r\n\r\nThis boundary never closes.",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"]["code"], "INVALID_EMAIL")

    def test_rejects_unsupported_file_type(self) -> None:
        response = self.request("message.txt", b"From: sender@example.com\n\nHello")

        self.assertEqual(response.status_code, 415)
        self.assertEqual(response.json()["detail"]["code"], "UNSUPPORTED_FILE_TYPE")

    def test_rejects_content_without_email_headers(self) -> None:
        response = self.request("not-an-email.eml", b"not an email")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"]["code"], "INVALID_EMAIL")

    def test_rejects_oversized_input_before_parsing(self) -> None:
        with patch("app.api.MAX_EMAIL_SIZE", 5):
            response = self.request("large.eml", b"From: sender@example.com\r\n\r\nHello")

        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json()["detail"]["code"], "FILE_TOO_LARGE")

    def test_health_reports_release_metadata(self) -> None:
        async def send_request() -> httpx.Response:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                return await client.get("/health")

        response = asyncio.run(send_request())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")
        self.assertEqual(response.json()["version"], "v1")

    def test_rate_limiter_rejects_requests_over_its_limit(self) -> None:
        limiter = RateLimiter(limit=1, window_seconds=60)
        self.assertEqual(limiter.check("client"), (True, 0, 0))
        allowed, remaining, retry_after = limiter.check("client")
        self.assertFalse(allowed)
        self.assertEqual(remaining, 0)
        self.assertGreater(retry_after, 0)

    def test_rapidapi_mode_rejects_requests_that_bypass_the_proxy(self) -> None:
        rapidapi_settings = Settings(
            api_key=None,
            rapidapi_proxy_secret="rapid-secret",
            max_upload_size=10 * 1024 * 1024,
            rate_limit_enabled=False,
            rate_limit_requests=60,
            rate_limit_window_seconds=60,
        )
        with patch("app.api.settings", rapidapi_settings):
            rejected = self.request("message.eml", b"From: sender@example.com\r\n\r\nHello")
            accepted = self.request(
                "message.eml",
                b"From: sender@example.com\r\n\r\nHello",
                headers={"X-RapidAPI-Proxy-Secret": "rapid-secret"},
            )

        self.assertEqual(rejected.status_code, 401)
        self.assertEqual(rejected.json()["detail"]["code"], "INVALID_PROXY_SECRET")
        self.assertEqual(accepted.status_code, 200)

    def test_public_legal_pages_remain_available_in_rapidapi_mode(self) -> None:
        rapidapi_settings = Settings(
            api_key=None,
            rapidapi_proxy_secret="rapid-secret",
            max_upload_size=10 * 1024 * 1024,
            rate_limit_enabled=False,
            rate_limit_requests=60,
            rate_limit_window_seconds=60,
        )

        async def send_request(path: str) -> httpx.Response:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                return await client.get(path)

        with patch("app.api.settings", rapidapi_settings):
            privacy = asyncio.run(send_request("/privacy"))
            terms = asyncio.run(send_request("/terms"))

        self.assertEqual(privacy.status_code, 200)
        self.assertIn("Moonfall Software", privacy.text)
        self.assertIn("moonfallsoftware@outlook.com", privacy.text)
        self.assertEqual(terms.status_code, 200)

    def test_openapi_documents_api_key_and_error_responses(self) -> None:
        async def send_request() -> httpx.Response:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                return await client.get("/openapi.json")

        schema = asyncio.run(send_request()).json()
        operation = schema["paths"]["/v1/analyze"]["post"]
        self.assertEqual(operation["security"], [{"ApiKeyAuth": []}])
        self.assertIn("ApiKeyAuth", schema["components"]["securitySchemes"])
        self.assertTrue({"401", "429"}.issubset(operation["responses"]))
        upload_schema = schema["components"]["schemas"]["Body_analyze_email_v1_analyze_post"]
        self.assertEqual(upload_schema["properties"]["file"]["format"], "binary")

    def test_flags_spoofed_sender_deceptive_links_and_dangerous_filename(self) -> None:
        response = self.request("phishing.eml", Path("sample-phishing-email.eml").read_bytes())

        self.assertEqual(response.status_code, 200)
        codes = {item["code"] for item in response.json()["findings"]}
        self.assertTrue({"SENDER_REPLY_TO_DOMAIN_MISMATCH", "URL_IP_ADDRESS", "URL_VISIBLE_TEXT_MISMATCH", "ATTACHMENT_DOUBLE_EXTENSION"}.issubset(codes))

    def test_header_injection_does_not_expose_unmodeled_headers(self) -> None:
        response = self.request(
            "injected-header.eml",
            b"From: sender@example.com\r\nTo: analyst@example.net\r\n"
            b"Subject: harmless\r\nX-Injected: secret-value\r\nBcc: hidden@example.net\r\n\r\nHello",
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertNotIn("X-Injected", response.text)
        self.assertNotIn("secret-value", response.text)
        self.assertNotIn("hidden@example.net", response.text)
        self.assertEqual(payload["message"]["recipients"], ["analyst@example.net"])

    def test_analysis_is_deterministic_for_the_same_input(self) -> None:
        content = Path("sample-phishing-email.eml").read_bytes()

        first = self.request("phishing.eml", content)
        second = self.request("phishing.eml", content)

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(first.json(), second.json())
