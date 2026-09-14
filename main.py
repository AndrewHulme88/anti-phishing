from email.utils import getaddresses

from fastapi import FastAPI, UploadFile, File, HTTPException
from fast_mail_parser import parse_email, ParseError
from models import AnalysisResponse

app = FastAPI()

MAX_EMAIL_SIZE = 10 * 1024 * 1024  # 10 MB


def normalize_recipients(header_value: str | None) -> list[str]:
    if not header_value:
        return []

    return [address for _, address in getaddresses([header_value]) if address]

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.post("/v1/analyze", response_model=AnalysisResponse)
async def parse_email_file(file: UploadFile = File(...)):
    content = await file.read(MAX_EMAIL_SIZE + 1)

    if not content:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "EMPTY_FILE",
                "message": "The uploaded email file is empty."
            }
        )

    if len(content) > MAX_EMAIL_SIZE:
        raise HTTPException(
            status_code=413,
            detail={
                "code": "FILE_TOO_LARGE",
                "message": "Email files must be 10 MB or smaller."
            }
        )
    
    try:
        email_object = parse_email(content)

        return {
            "message": {
                "subject": email_object.subject,
                "from": email_object.headers.get("From"),
                "recipients": normalize_recipients(email_object.headers.get("To")),
                "date": email_object.headers.get("Date")
            },
            "text_body": email_object.text_plain,
            "html_body": email_object.text_html,
            "attachments": [
                {"filename": att.filename, "content_type": att.mimetype}
                for att in email_object.attachments
            ]
        }
    except ParseError as error:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "INVALID_EMAIL",
                "message": "Invalid or corrupted email file structure."
            }
        ) from error