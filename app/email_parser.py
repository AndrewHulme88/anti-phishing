import re
from collections.abc import Sequence
from datetime import UTC
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser
from urllib.parse import urlsplit, urlunsplit

from fast_mail_parser import parse_email

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)

class LinkExtractor(HTMLParser):
    """Collect link destinations and their visible text without rendering HTML."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str | None]] = []
        self._href: str | None = None
        self._text_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text_parts = []

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._href is not None:
            visible_text = " ".join("".join(self._text_parts).split()) or None
            self.links.append((self._href, visible_text))
            self._href = None
            self._text_parts = []

def normalize_text(value: str | Sequence[str] | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value

    parts = [part for part in value if isinstance(part, str) and part]
    return "\n".join(parts) or None

def first_text(value: str | Sequence[str] | None) -> str | None:
    if isinstance(value, str):
        return value or None
    if value:
        return next((part for part in value if isinstance(part, str) and part), None)
    return None

def normalize_date(value: str | Sequence[str] | None) -> str | None:
    date_value = first_text(value)
    if not date_value:
        return None

    try:
        parsed_date = parsedate_to_datetime(date_value)
    except (TypeError, ValueError):
        return None

    if parsed_date.tzinfo is None:
        parsed_date = parsed_date.replace(tzinfo=UTC)
    return parsed_date.astimezone(UTC).isoformat()

def normalize_recipients(header_value: str | Sequence[str] | None) -> list[str]:
    if not header_value:
        return []

    values = [header_value] if isinstance(header_value, str) else header_value
    return [address for _, address in getaddresses(values) if address]

def normalize_url(value: str) -> str | None:
    candidate = value.rstrip(".,;:!?)]}\"'")
    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return None

    if parsed.scheme.lower() not in {"http", "https"} or not hostname:
        return None

    scheme = parsed.scheme.lower()
    netloc = hostname.lower()
    if port and (scheme, port) not in {("http", 80), ("https", 443)}:
        netloc = f"{netloc}:{port}"
    return urlunsplit((scheme, netloc, parsed.path or "/", parsed.query, parsed.fragment))

def extract_urls(text_body: str | None, html_body: str | None) -> list[dict[str, str | None]]:
    candidates: list[tuple[str, str | None]] = []
    if text_body:
        candidates.extend((match.group(), None) for match in URL_PATTERN.finditer(text_body))
    if html_body:
        extractor = LinkExtractor()
        extractor.feed(html_body)
        candidates.extend(extractor.links)

    urls: list[dict[str, str | None]] = []
    seen: set[tuple[str, str | None]] = set()
    for destination, visible_text in candidates:
        normalized = normalize_url(destination)
        key = (normalized, visible_text)
        if normalized and key not in seen:
            seen.add(key)
            urls.append({"destination": normalized, "visible_text": visible_text})
    return urls

def attachment_size(attachment: object) -> int | None:
    content = getattr(attachment, "content", None)
    return len(content) if isinstance(content, bytes) else None

def parse_email_content(content: bytes) -> dict[str, object]:
    """Parse an email and convert parser-specific values into the API contract."""
    email_object = parse_email(content)
    if not email_object.headers:
        raise ValueError("Email has no RFC 5322 headers.")

    text_body = normalize_text(email_object.text_plain)
    html_body = normalize_text(email_object.text_html)
    return {
        "message": {
            "subject": first_text(email_object.subject),
            "from": first_text(email_object.headers.get("From")),
            "recipients": normalize_recipients(email_object.headers.get("To")),
            "date": normalize_date(email_object.headers.get("Date")),
        },
        "text_body": text_body,
        "html_body": html_body,
        "urls": extract_urls(text_body, html_body),
        "attachments": [
            {
                "filename": first_text(attachment.filename),
                "content_type": first_text(attachment.mimetype),
                "size": attachment_size(attachment),
            }
            for attachment in email_object.attachments
        ],
        "findings": [],
        "risk": {"score": 0, "level": "low"},
    }
