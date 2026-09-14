from fastapi import FastAPI, UploadFile, File
from fast_mail_parser import parse_email, ParseError

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Hello World"}

@app.post("/v1/analyze")
async def parse_email_file(file: UploadFile = File(...)):
    content = await file.read()

    try:
        email_object = parse_email(content)

        return {
            "subject": email_object.subject,
            "from": email_object.headers.get("From"),
            "to": email_object.headers.get("To"),
            "date": email_object.headers.get("Date"),
            "text_body": email_object.text_plain,
            "html_body": email_object.text_html,
            "attachments": [
                {"filename": att.filename, "content_type": att.mimetype}
                for att in email_object.attachments
            ]
        }
    except ParseError:
        return {"error": "Invalid or corrupted email file structure."}