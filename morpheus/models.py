from typing import Literal

from pydantic import BaseModel, Field

class ConfigUpdate(BaseModel):
    automatic_high_confidence: bool | None = None
    automatic_quarantine: bool | None = None
    download_monitoring: bool | None = None
    automatic_quarantine_downloads: bool | None = None
    dns_entropy_monitoring: bool | None = None
    powershell_log_monitoring: bool | None = None
    process_tree_monitoring: bool | None = None
    canary_monitoring: bool | None = None
    download_directory: str | None = Field(default=None, min_length=1, max_length=32768)
    download_confidence_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    high_confidence_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    poll_interval_seconds: float | None = Field(default=None, ge=1.0, le=3600.0)

class ScanFileRequest(BaseModel):
    path: str = Field(min_length=1, max_length=32768)

class ScanFolderRequest(BaseModel):
    path: str = Field(min_length=1, max_length=32768)

class CodeReviewRequest(BaseModel):
    path: str = Field(min_length=1, max_length=32768)

class AssistantMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=2000)

class AssistantChatRequest(BaseModel):
    model: str = Field(min_length=1, max_length=128)
    message: str = Field(min_length=1, max_length=2000)
    history: list[AssistantMessage] = Field(default_factory=list, max_length=8)

class QuarantineRequest(BaseModel):
    path: str = Field(min_length=1, max_length=32768)

class SettingsPasswordRequest(BaseModel):
    password: str = Field(min_length=10, max_length=1024)
    current_password: str | None = Field(default=None, max_length=1024)

class FirewallRuleRequest(BaseModel):
    remote_ip: str = Field(min_length=1, max_length=64)
