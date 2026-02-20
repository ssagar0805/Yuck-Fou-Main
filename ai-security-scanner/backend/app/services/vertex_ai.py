"""
Vertex AI / Gemini 2.0 Flash client.

Key design decisions:
- vertexai.init() is called once at construction time (not per-request)
- generate_content() is synchronous in the SDK; we wrap it with
  asyncio.to_thread() so it doesn't block the FastAPI event loop
- A single shared instance is created at module level and reused
"""

import asyncio
import json
import os
import traceback

import vertexai
from vertexai.preview.generative_models import GenerativeModel, GenerationConfig
from tenacity import retry, stop_after_attempt, wait_exponential

from app.core.config import settings
from app.core.logging import logger


# ---------------------------------------------------------------------------
# Fallback response returned when the LLM call fails
# ---------------------------------------------------------------------------
_FALLBACK = {
    "found": False,
    "severity": "Low",
    "confidence": 0.0,
    "evidence": [],
    "description": "LLM analysis unavailable — rule-based results only.",
    "attack_scenario": "",
    "remediation": "Manual review recommended.",
}


class VertexAIClient:
    """Thin async wrapper around the Vertex AI Gemini SDK."""

    def __init__(self) -> None:
        creds = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "NOT SET")
        logger.info("=== VERTEX AI INIT ===")
        logger.info("  Project  : %s", settings.VERTEX_AI_PROJECT)
        logger.info("  Location : %s", settings.VERTEX_AI_LOCATION)
        logger.info("  Model    : %s", settings.VERTEX_AI_MODEL)
        logger.info("  Creds    : %s", creds)
        logger.info("  Creds exists: %s", os.path.exists(creds) if creds != "NOT SET" else False)

        vertexai.init(
            project=settings.VERTEX_AI_PROJECT,
            location=settings.VERTEX_AI_LOCATION,
        )
        self._model = GenerativeModel(settings.VERTEX_AI_MODEL)
        self._generation_config = GenerationConfig(
            temperature=0.1,        # Low for deterministic security analysis
            max_output_tokens=8192,
            top_p=0.95,
            response_mime_type="application/json",
        )
        logger.info("VertexAIClient initialised successfully | project=%s | model=%s",
            settings.VERTEX_AI_PROJECT,
            settings.VERTEX_AI_MODEL,
        )

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def _generate_with_retry(self, prompt: str):
        return await asyncio.to_thread(
            self._model.generate_content,
            prompt,
            generation_config=self._generation_config,
        )

    async def analyze_with_llm(self, prompt: str) -> dict:
        """
        Send a prompt to Gemini and return a parsed JSON dict.

        Uses asyncio.to_thread() because the Vertex AI SDK's
        generate_content() is synchronous and would otherwise block
        the FastAPI event loop during the 2-4 second API call.
        """
        try:
            response = await self._generate_with_retry(prompt)

            # Guard against empty or blocked responses
            if not response.candidates:
                logger.warning("Gemini returned no candidates (likely safety filter).")
                return {**_FALLBACK, "description": "Response blocked by safety filter."}

            raw_text = response.text.strip()

            # Strip markdown code fences if Gemini wraps JSON in them
            if raw_text.startswith("```"):
                raw_text = raw_text.split("```")[1]
                if raw_text.startswith("json"):
                    raw_text = raw_text[4:]
                raw_text = raw_text.strip()

            result = json.loads(raw_text)
            return result

        except json.JSONDecodeError as exc:
            logger.error("Gemini returned non-JSON: %s | error: %s", response.text[:200], exc)
            return {**_FALLBACK, "description": f"LLM returned malformed JSON: {exc}"}

        except Exception as exc:
            logger.error("Vertex AI API call FAILED: %s: %s", type(exc).__name__, exc)
            logger.error("Full traceback:\n%s", traceback.format_exc())
            return {**_FALLBACK, "description": f"LLM analysis error: {type(exc).__name__}: {exc}"}


# ---------------------------------------------------------------------------
# Module-level singleton — created lazily on first use to avoid crashing
# the import if Vertex AI credentials are not yet configured.
# ---------------------------------------------------------------------------
_client: VertexAIClient | None = None


def get_vertex_client() -> VertexAIClient:
    """Return the shared VertexAIClient, creating it on first call."""
    global _client
    if _client is None:
        _client = VertexAIClient()
    return _client
