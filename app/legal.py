"""Public legal and privacy pages for the hosted API."""

from html import escape


BUSINESS_NAME = "Moonfall Software"
SUPPORT_EMAIL = "moonfallsoftware@outlook.com"
EFFECTIVE_DATE = "15 September 2026"


def page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title)} | {BUSINESS_NAME}</title>
<style>body{{font-family:system-ui,sans-serif;line-height:1.55;max-width:760px;margin:3rem auto;padding:0 1rem;color:#17202a}}h1,h2{{line-height:1.2}}a{{color:#075db5}}</style>
</head><body><main><h1>{escape(title)}</h1>{body}</main></body></html>"""


PRIVACY_PAGE = page(
    "Privacy Policy",
    f"""
<p>Effective date: {EFFECTIVE_DATE}</p>
<p>{BUSINESS_NAME} provides the Phishing Email Analyzer API. This policy explains how the API handles personal information contained in uploaded email messages.</p>
<h2>Information processed</h2>
<p>The API processes the email file and its contents, including message headers, body text, URLs, attachment metadata, and any personal information they contain, solely to produce the requested analysis response.</p>
<h2>Storage and disclosure</h2>
<p>Email uploads are processed in memory. Moonfall Software does not intentionally persist raw uploaded email messages or attachment contents. The service does not execute attachments, follow extracted links, or perform external reputation or DNS lookups. Operational logs are designed to exclude email content, headers, attachments, addresses, and API secrets.</p>
<p>The API is delivered through hosting and API-gateway providers. Those providers may process network, security, billing, and operational data to provide their services. API customers should review their own agreements and configure gateway logging appropriately before uploading sensitive data.</p>
<h2>Security and retention</h2>
<p>Use HTTPS and keep API credentials confidential. Because raw uploads are not intentionally retained by the application, Moonfall Software generally cannot retrieve, correct, or delete a previously submitted email message.</p>
<h2>Your responsibilities</h2>
<p>You must have the authority to submit each email message and must not upload information unlawfully. Do not submit highly sensitive information unless you have assessed the suitability of the service and its providers for that use.</p>
<h2>Questions or complaints</h2>
<p>Contact <a href="mailto:{SUPPORT_EMAIL}">{SUPPORT_EMAIL}</a>. We may update this policy by publishing a revised version on this page.</p>
""",
)


TERMS_PAGE = page(
    "Terms of Service",
    f"""
<p>Effective date: {EFFECTIVE_DATE}</p>
<p>These terms govern your use of the Phishing Email Analyzer API provided by {BUSINESS_NAME}.</p>
<h2>Permitted use</h2>
<p>You may use the API only for lawful purposes and only with email messages you are authorised to submit. You must comply with applicable law, these terms, and the terms of the API marketplace or gateway through which you access the API.</p>
<h2>Service limitations</h2>
<p>The API provides deterministic, offline indicators to assist review. It is not a guarantee that a message is safe or malicious, and it is not a substitute for professional security controls, investigation, or human judgement. The service does not execute attachments or visit URLs.</p>
<h2>Availability and changes</h2>
<p>The service may be changed, suspended, rate-limited, or discontinued. We may update these terms by publishing a revised version on this page.</p>
<h2>Disclaimer</h2>
<p>To the extent permitted by law, the service is provided "as is" and "as available" without warranties of any kind. You are responsible for decisions and actions taken using API results.</p>
<h2>Contact</h2>
<p>Questions about these terms can be sent to <a href="mailto:{SUPPORT_EMAIL}">{SUPPORT_EMAIL}</a>.</p>
""",
)
