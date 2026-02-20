"""
Application configuration using pydantic-settings.
Loads from environment variables and optional .env file.
"""

import os
from pathlib import Path
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Vertex AI / GCP Configuration
    VERTEX_AI_PROJECT: str
    VERTEX_AI_LOCATION: str = "us-central1"
    VERTEX_AI_MODEL: str = "gemini-2.0-flash-exp"

    # GCP Credentials — path to service account JSON key file
    # Can be relative (resolved from backend/ directory) or absolute.
    GOOGLE_APPLICATION_CREDENTIALS: str = ""

    # Logging
    LOG_LEVEL: str = "INFO"

    # App
    APP_TITLE: str = "AI Security Scanner"
    APP_VERSION: str = "1.0.0"

    # CORS
    ALLOWED_ORIGINS: list[str] = ["*"]

    # File limits
    MAX_FILE_SIZE_MB: int = 10

    # Reports
    REPORT_DIR: str = "static/reports"

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
        "extra": "ignore",
    }

    def model_post_init(self, __context) -> None:
        """Apply GCP credentials to os.environ so google-auth picks them up."""
        if self.GOOGLE_APPLICATION_CREDENTIALS:
            # Resolve relative path against the directory containing this file
            # (backend/) so that 'gcp-credentials.json' always works.
            creds_path = Path(self.GOOGLE_APPLICATION_CREDENTIALS)
            if not creds_path.is_absolute():
                # __file__ is .../backend/app/core/config.py
                # .parent      = .../backend/app/core/
                # .parent.parent = .../backend/app/
                # .parent.parent.parent = .../backend/   <-- this is what we want
                backend_dir = Path(__file__).resolve().parent.parent.parent
                creds_path = backend_dir / creds_path
            abs_path = str(creds_path.resolve())
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = abs_path

        # Also ensure project/location are available as env vars for SDKs
        # that fall back to GOOGLE_CLOUD_PROJECT
        if self.VERTEX_AI_PROJECT:
            os.environ.setdefault("GOOGLE_CLOUD_PROJECT", self.VERTEX_AI_PROJECT)


@lru_cache()
def get_settings() -> Settings:
    """Return cached settings instance."""
    return Settings()


# Convenience export
settings = get_settings()
