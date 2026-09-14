from typing import Literal
from pydantic import BaseModel, Field

class AttachmentInfo(BaseModel):
    filename: str | None
    content_type: str | None
    size: int | None = Field(default=None, ge=0)

class URLInfo(BaseModel):
    visible_text: str | None = None
    destination: str

class Finding(BaseModel):
    code: str
    severity: Literal["low", "medium", "high"]
    title: str
    evidence: str | None = None
    remediation: str | None = None

class RiskAssessment(BaseModel):
    score: int = Field(ge=0, le=100)
    level: Literal["low", "medium", "high"]

class ErrorDetail(BaseModel):
    code: str
    message: str

class ErrorResponse(BaseModel):
    detail: ErrorDetail

class MessageInfo(BaseModel):
    subject: str | None
    sender: str | None = Field(alias="from")
    recipients: list[str]
    date: str | None

class AnalysisResponse(BaseModel):
    message: MessageInfo
    text_body: str | None
    html_body: str | None
    urls: list[URLInfo]
    attachments: list[AttachmentInfo]
    findings: list[Finding]
    risk: RiskAssessment
