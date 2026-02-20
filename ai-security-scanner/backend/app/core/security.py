"""
Security utilities: file validation, content sanitization.
"""

import re
from fastapi import HTTPException, UploadFile

ALLOWED_EXTENSIONS = {"txt", "json", "yaml", "yml", "py"}
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB


def validate_upload(file: UploadFile) -> str:
    """
    Validate uploaded file extension and return normalized file_type.
    Raises HTTPException on invalid input.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided.")

    ext = file.filename.rsplit(".", 1)[-1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '.{ext}'. Allowed: {sorted(ALLOWED_EXTENSIONS)}",
        )

    # Normalize yaml/yml → yaml
    return "yaml" if ext == "yml" else ext


def sanitize_content(content: str) -> str:
    """
    Basic content sanitization — strip null bytes and excessive whitespace.
    Does NOT strip legitimate code characters.
    """
    content = content.replace("\x00", "")
    # Collapse runs of 4+ blank lines into 2
    content = re.sub(r"\n{4,}", "\n\n", content)
    return content


def check_file_size(content: bytes) -> None:
    """Raise HTTPException if content exceeds the size limit."""
    if len(content) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size is {MAX_FILE_SIZE_BYTES // (1024*1024)} MB.",
        )
