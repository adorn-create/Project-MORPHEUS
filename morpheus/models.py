from pydantic import BaseModel, ConfigDict, Field

class ConfigUpdate(BaseModel):
    automatic_high_confidence: bool | None = None
    automatic_quarantine: bool | None = None
    automatic_isolation: bool | None = None
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
    scan_max_file_bytes: int | None = Field(default=None, ge=1024, le=10_737_418_240)
    scan_max_folder_bytes: int | None = Field(default=None, ge=1024, le=109_951_162_7776)
    scan_max_folder_files: int | None = Field(default=None, ge=1, le=100000)
    scan_timeout_seconds: float | None = Field(default=None, ge=1.0, le=3600.0)

class ScanFileRequest(BaseModel):
    path: str = Field(min_length=1, max_length=32768)

class AntivirusScanRequest(BaseModel):
    path: str = Field(min_length=1, max_length=32768)

class ScanFolderRequest(BaseModel):
    path: str = Field(min_length=1, max_length=32768)

class CodeReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1, max_length=32768)

class AssistantChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str = Field(min_length=1, max_length=2000)

class QuarantineRequest(BaseModel):
    path: str = Field(min_length=1, max_length=32768)

class SettingsPasswordRequest(BaseModel):
    password: str = Field(min_length=10, max_length=1024)
    current_password: str | None = Field(default=None, max_length=1024)

class PasskeyRegistrationOptionsRequest(BaseModel):
    bootstrap_password: str | None = Field(default=None, max_length=1024)

class PasskeyCeremonyRequest(BaseModel):
    ceremony_id: str = Field(min_length=1, max_length=128)
    credential: dict

class PasskeyRecoveryRequest(BaseModel):
    code: str = Field(min_length=32, max_length=39)
