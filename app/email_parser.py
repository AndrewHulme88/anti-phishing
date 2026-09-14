import re
from collections.abc import Sequence
from datetime import UTC
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser
from urllib.parse import urlsplit, urlunsplit

from fast_mail_parser import parse_email

URL_PATTERN = re.compile(
    r"(?:(?:https?|ftp)://|(?:javascript|data|file|mailto):)[^\s<>\"']+",
    re.IGNORECASE,
)
DOMAIN_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$", re.IGNORECASE)
IPV4_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

SHORTENER_DOMAINS = {"bit.ly", "buff.ly", "goo.gl", "is.gd", "ow.ly", "t.co", "tinyurl.com", "trib.al"}
RISKY_EXTENSIONS = {"ade", "adp", "apk", "app", "bat", "cab", "cmd", "com", "cpl", "dll", "dmg", "exe", "hta", "img", "iso", "jar", "js", "jse", "lnk", "msi", "msp", "pif", "ps1", "reg", "scr", "vbe", "vbs", "wsf"}

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

    scheme = parsed.scheme.lower()
    if not scheme:
        return None
    if scheme not in {"http", "https"}:
        return urlunsplit((scheme, parsed.netloc, parsed.path, parsed.query, parsed.fragment))
    if not hostname:
        return None
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


def header_values(headers: dict[str, object], name: str) -> list[str]:
    """Return all values for a header, independent of the parser's casing."""
    values: list[str] = []
    for key, value in headers.items():
        if key.lower() != name.lower():
            continue
        if isinstance(value, str):
            values.append(value)
        elif isinstance(value, Sequence):
            values.extend(item for item in value if isinstance(item, str))
    return values


def address_domain(value: str | None) -> str | None:
    if not value:
        return None
    addresses = getaddresses([value])
    if not addresses or not addresses[0][1] or "@" not in addresses[0][1]:
        return None
    return addresses[0][1].rsplit("@", 1)[1].lower()


def finding(code: str, severity: str, title: str, evidence: str, remediation: str) -> dict[str, str]:
    return {"code": code, "severity": severity, "title": title, "evidence": evidence, "remediation": remediation}


def authentication_status(values: list[str], mechanism: str) -> str | None:
    pattern = re.compile(rf"\b{re.escape(mechanism)}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b", re.I)
    for value in values:
        match = pattern.search(value)
        if match:
            return match.group(1).lower()
    return None


def received_spf_status(values: list[str]) -> str | None:
    pattern = re.compile(r"^\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b", re.I)
    for value in values:
        match = pattern.search(value)
        if match:
            return match.group(1).lower()
    return None


def analyze_email(message: dict[str, object], text_body: str | None, html_body: str | None, urls: list[dict[str, str | None]], attachments: list[dict[str, object]], headers: dict[str, object]) -> tuple[list[dict[str, str]], dict[str, object]]:
    """Apply stable, offline rules. Scores are capped at 100 and intentionally additive."""
    findings: list[dict[str, str]] = []
    sender = message.get("from") if isinstance(message.get("from"), str) else None
    reply_to = message.get("reply_to") if isinstance(message.get("reply_to"), str) else None
    sender_domain, reply_domain = address_domain(sender), address_domain(reply_to)
    if sender_domain and reply_domain and sender_domain != reply_domain:
        findings.append(finding("SENDER_REPLY_TO_DOMAIN_MISMATCH", "high", "Reply-To domain differs from sender", f"From uses {sender_domain}; Reply-To uses {reply_domain}.", "Verify the sender through an independent channel before replying."))

    for url in urls:
        destination = url["destination"] or ""
        visible = url.get("visible_text")
        parsed = urlsplit(destination)
        host = (parsed.hostname or "").lower()
        if parsed.scheme not in {"http", "https"}:
            findings.append(finding("URL_UNSAFE_SCHEME", "high", "Link uses an unsafe scheme", destination, "Do not open this link; use the organisation's known website instead."))
            continue
        if parsed.scheme == "http":
            findings.append(finding("URL_INSECURE_HTTP", "low", "Link is not encrypted", destination, "Prefer HTTPS links and verify the destination before entering information."))
        if IPV4_PATTERN.fullmatch(host):
            findings.append(finding("URL_IP_ADDRESS", "high", "Link uses an IP address", destination, "Do not use IP-address links for account or payment activity."))
        if "xn--" in host:
            findings.append(finding("URL_PUNYCODE", "high", "Link contains a punycode domain", host, "Inspect the domain carefully and use a trusted bookmarked site."))
        if host in SHORTENER_DOMAINS:
            findings.append(finding("URL_SHORTENER", "medium", "Link uses a URL shortener", destination, "Expand and verify the final destination before opening it."))
        if visible:
            visible_host = urlsplit(visible if "://" in visible else f"https://{visible}").hostname
            if visible_host and DOMAIN_PATTERN.fullmatch(visible_host) and visible_host.lower() != host:
                findings.append(finding("URL_VISIBLE_TEXT_MISMATCH", "high", "Visible link domain differs from destination", f"Visible: {visible_host}; destination: {host}.", "Do not follow the link; navigate to the expected site directly."))

    body = "\n".join(part for part in (text_body, html_body) if part).lower()
    content_rules = [
        ("CONTENT_URGENCY", "medium", "Message creates urgency", r"\b(urgent|immediately|asap|act now|within \d+ hours?)\b", "Slow down and verify the request independently."),
        ("CONTENT_CREDENTIAL_REQUEST", "high", "Message requests credentials", r"\b(password|passcode|login credentials|sign[ -]?in credentials)\b", "Never provide credentials from an unsolicited message."),
        ("CONTENT_ACCOUNT_SUSPENSION", "medium", "Message threatens account suspension", r"\b(account (?:will be )?(?:suspended|disabled|locked)|suspend your account)\b", "Check account status through the official service directly."),
        ("CONTENT_PAYMENT_PRESSURE", "medium", "Message pressures for payment", r"\b(pay(?:ment)? (?:immediately|now|today)|overdue (?:invoice|payment)|wire transfer|gift cards?)\b", "Verify payment requests using a known contact method."),
        ("CONTENT_SENSITIVE_INFORMATION_REQUEST", "high", "Message requests sensitive information", r"\b(social security|credit card|bank account|tax file number|date of birth)\b", "Do not disclose sensitive information by email."),
    ]
    for code, severity, title, pattern, remediation in content_rules:
        match = re.search(pattern, body)
        if match:
            findings.append(finding(code, severity, title, match.group(0), remediation))

    for attachment in attachments:
        filename = attachment.get("filename")
        if not isinstance(filename, str):
            continue
        suffixes = [part.lower() for part in filename.rsplit(".")[1:]]
        if len(suffixes) >= 2 and suffixes[-1] in RISKY_EXTENSIONS:
            findings.append(finding("ATTACHMENT_DOUBLE_EXTENSION", "high", "Attachment has a suspicious double extension", filename, "Do not open the attachment; confirm it with the sender independently."))
        elif suffixes and suffixes[-1] in RISKY_EXTENSIONS:
            findings.append(finding("ATTACHMENT_RISKY_EXTENSION", "high", "Attachment has a risky file extension", filename, "Do not open or execute the attachment."))

    auth_results = header_values(headers, "Authentication-Results")
    spf = authentication_status(auth_results, "spf") or received_spf_status(header_values(headers, "Received-SPF"))
    dkim = authentication_status(auth_results, "dkim")
    dmarc = authentication_status(auth_results, "dmarc")
    # A signature alone is not proof of a pass, but retaining its presence makes available authentication data explicit when no result header exists.
    if dkim is None and header_values(headers, "DKIM-Signature"):
        dkim = "present"
    authentication = {"spf": spf, "dkim": dkim, "dmarc": dmarc, "results": auth_results}
    for mechanism in ("spf", "dkim", "dmarc"):
        status = authentication[mechanism]
        if status in {"fail", "softfail", "permerror", "temperror"}:
            findings.append(finding(f"AUTH_{mechanism.upper()}_{status.upper()}", "high", f"{mechanism.upper()} authentication did not pass", f"{mechanism}={status}", "Treat the sender identity as unverified and validate the message independently."))

    weights = {"low": 5, "medium": 12, "high": 25}
    score = min(100, sum(weights[item["severity"]] for item in findings))
    level = "high" if score >= 50 else "medium" if score >= 20 else "low"
    return findings, {"score": score, "level": level, "authentication": authentication}

def attachment_size(attachment: object) -> int | None:
    content = getattr(attachment, "content", None)
    return len(content) if isinstance(content, bytes) else None

def parse_email_content(content: bytes) -> dict[str, object]:
    """Parse an email and convert parser-specific values into the API contract."""
    # fast-mail-parser is intentionally permissive. Use the standard library's
    # defect reporting as an input-boundary check so truncated multipart bodies
    # do not get treated as complete messages.
    structure = BytesParser(policy=policy.default).parsebytes(content)
    if structure.defects:
        raise ValueError("Email contains malformed MIME structure.")

    email_object = parse_email(content)
    if not email_object.headers:
        raise ValueError("Email has no RFC 5322 headers.")

    headers = email_object.headers
    text_body = normalize_text(email_object.text_plain)
    html_body = normalize_text(email_object.text_html)
    message = {
            "subject": first_text(headers.get("Subject")),
            "from": first_text(headers.get("From")),
            "recipients": normalize_recipients(headers.get("To")),
            "reply_to": first_text(headers.get("Reply-To")),
            "date": normalize_date(email_object.headers.get("Date")),
    }
    urls = extract_urls(text_body, html_body)
    attachments = [
            {
                "filename": first_text(attachment.filename),
                "content_type": first_text(attachment.mimetype),
                "size": attachment_size(attachment),
            }
            for attachment in email_object.attachments
        ]
    findings, assessment = analyze_email(message, text_body, html_body, urls, attachments, headers)
    return {"message": message, "text_body": text_body, "html_body": html_body, "urls": urls, "attachments": attachments, "findings": findings, "risk": {"score": assessment["score"], "level": assessment["level"]}, "authentication": assessment["authentication"]}
