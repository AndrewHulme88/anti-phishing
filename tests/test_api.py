import asyncio
import unittest
from pathlib import Path

import httpx

from app.api import app


class AnalyzeEndpointTests(unittest.TestCase):
    def request(self, filename: str, content: bytes) -> httpx.Response:
        async def send_request() -> httpx.Response:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                return await client.post(
                    "/v1/analyze",
                    files={"file": (filename, content, "message/rfc822")},
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

    def test_rejects_unsupported_file_type(self) -> None:
        response = self.request("message.txt", b"From: sender@example.com\n\nHello")

        self.assertEqual(response.status_code, 415)
        self.assertEqual(response.json()["detail"]["code"], "UNSUPPORTED_FILE_TYPE")

    def test_rejects_content_without_email_headers(self) -> None:
        response = self.request("not-an-email.eml", b"not an email")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"]["code"], "INVALID_EMAIL")
