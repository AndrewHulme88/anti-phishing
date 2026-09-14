from pydantic import BaseModel, Field

class AttachmentInfo(BaseModel):
    filename: str | None
    content_type: str | None
    size: int | None = None

class MessageInfo(BaseModel):
    subject: str | None
    sender: str | None = Field(alias="from")
    recipients: list[str]
    date: str | None

class AnalysisResponse(BaseModel):
    message: MessageInfo
    text_body: str | None
    html_body: str | None
    attachments: list[AttachmentInfo]