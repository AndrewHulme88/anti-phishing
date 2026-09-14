from pathlib import PurePath
from fastapi import FastAPI, File, HTTPException, UploadFile
from fast_mail_parser import ParseError
from app.email_parser import parse_email_content
from app.models import AnalysisResponse, ErrorResponse

app = FastAPI(title="Phishing Email Analyzer")

MAX_EMAIL_SIZE = 10 * 1024 * 1024  # 10 MB

@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.post(
    "/v1/analyze",
    response_model=AnalysisResponse,
    responses={400: {"model": ErrorResponse}, 413: {"model": ErrorResponse}, 415: {"model": ErrorResponse}},
)
async def analyze_email(file: UploadFile = File(...)) -> dict[str, object]:
    if not file.filename or PurePath(file.filename).suffix.lower() != ".eml":
        raise HTTPException(
            status_code=415,
            detail={"code": "UNSUPPORTED_FILE_TYPE", "message": "Only .eml email files are supported."},
        )

    content = await file.read(MAX_EMAIL_SIZE + 1)
    if not content:
        raise HTTPException(
            status_code=400,
            detail={"code": "EMPTY_FILE", "message": "The uploaded email file is empty."},
        )
    if len(content) > MAX_EMAIL_SIZE:
        raise HTTPException(
            status_code=413,
            detail={"code": "FILE_TOO_LARGE", "message": "Email files must be 10 MB or smaller."},
        )

    try:
        return parse_email_content(content)
    except (ParseError, ValueError) as error:
        raise HTTPException(
            status_code=400,
            detail={"code": "INVALID_EMAIL", "message": "Invalid or corrupted email file structure."},
        ) from error
