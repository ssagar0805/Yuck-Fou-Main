"""
Pydantic request models for the scan API.
"""

from typing import Literal
from pydantic import BaseModel, field_validator


ALLOWED_FILE_TYPES = {"json", "yaml", "txt", "py"}


class ScanRequest(BaseModel):
    """Represents a file submitted for vulnerability scanning."""

    file_content: str
    file_type: Literal["json", "yaml", "txt", "py"]

    @field_validator("file_content")
    @classmethod
    def content_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("file_content must not be empty.")
        return v

    @field_validator("file_type")
    @classmethod
    def file_type_allowed(cls, v: str) -> str:
        v = v.lower()
        if v not in ALLOWED_FILE_TYPES:
            raise ValueError(
                f"file_type '{v}' is not supported. Allowed: {sorted(ALLOWED_FILE_TYPES)}"
            )
        return v

    model_config = {"str_strip_whitespace": True}
