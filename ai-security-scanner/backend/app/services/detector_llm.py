"""
LLM-powered detection layer (Layer 2 of the hybrid detection engine).

Uses Vertex AI Gemini 2.0 Flash with OWASP knowledge base context
to perform deep contextual analysis beyond what rules can catch.

Design notes:
- Each scan function receives parsed_data but passes only its RELEVANT
  sub-section to Gemini. This is critical for correct category routing.
- Knowledge base files are loaded lazily (not at import time).
- Each scan function is independently async (run in parallel via gather()).
- The client is reused across calls (singleton via get_vertex_client()).
"""

import asyncio
import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.core.logging import logger
from app.services.vertex_ai import get_vertex_client
from app.services.parser import get_line_number

# ---------------------------------------------------------------------------
# Knowledge base loading (lazy, cached)
# ---------------------------------------------------------------------------

KB_PATH = Path(__file__).parent.parent / "knowledge_base"

_KB_FILES = {
    "LLM01:2025": "LLM01_prompt_injection.md",
    "LLM02:2025": "LLM02_sensitive_info_disclosure.md",
    "LLM03:2025": "LLM03_supply_chain.md",
    "LLM04:2025": "LLM04_data_and_model_poisoning.md",
    "LLM05:2025": "LLM05_improper_output_handling.md",
    "LLM06:2025": "LLM06_excessive_agency.md",
    "LLM07:2025": "LLM07_system_prompt_leakage.md",
    "LLM08:2025": "LLM08_vector_and_embedding_weaknesses.md",
    "LLM09:2025": "LLM09_misinformation.md",
    "LLM10:2025": "LLM10_unbounded_consumption.md",
}


@lru_cache(maxsize=10)
def _load_kb(category: str) -> str:
    """Load and cache a knowledge base file. Returns empty string on error."""
    filename = _KB_FILES.get(category, "")
    if not filename:
        return ""
    path = KB_PATH / filename
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        logger.error("Knowledge base file not found: %s", path)
        return f"[Knowledge base for {category} not available]"
    except Exception as exc:
        logger.error("Error loading KB %s: %s", path, exc)
        return ""


# ---------------------------------------------------------------------------
# Prompt builder — takes FOCUSED content, not full parsed_data
# ---------------------------------------------------------------------------

_JSON_SCHEMA = """{
  "found": true or false,
  "severity": "Critical" or "High" or "Medium" or "Low",
  "confidence": 0.0 to 1.0,
  "evidence": ["specific quote from config", "another indicator"],
  "description": "Detailed explanation of the vulnerability and why it is a risk",
  "attack_scenario": "Concrete example of how an attacker could exploit this",
  "remediation": "Specific, actionable steps to fix this vulnerability",
  "owasp_reference": "Specific OWASP citation (e.g. LLM01:2025 Section 2.1)"
}"""


def _build_prompt(
    category: str,
    category_name: str,
    task_description: str,
    focused_content: Any,  # The specific section for this category
) -> str:
    """Build an LLM prompt using ONLY the relevant content section."""
    kb_content = _load_kb(category)
    # Serialize the focused content
    if isinstance(focused_content, str):
        content_str = focused_content
    else:
        content_str = json.dumps(focused_content, indent=2, default=str)

    if len(content_str) > 8000:
        content_str = content_str[:8000] + "\n... [truncated for context window]"

    return f"""You are a senior cybersecurity expert specializing in OWASP Top 10 for LLM Applications.
Your task is to analyze the following AI agent configuration section for {category} ({category_name}) vulnerabilities ONLY.

## OWASP KNOWLEDGE BASE FOR {category}
{kb_content}

## CONFIGURATION SECTION TO ANALYZE (focused on {category_name})
{content_str}

## ANALYSIS TASK
{task_description}

IMPORTANT: Only report findings for {category} ({category_name}).
Do NOT report findings for other OWASP categories — those are handled by separate scanners.
Be precise: only flag real vulnerabilities with concrete evidence from the configuration above.
Assign confidence based on certainty of evidence.

## REQUIRED OUTPUT FORMAT
Respond ONLY with valid JSON matching this exact schema:
{_JSON_SCHEMA}
"""


def _get_focused_content(category: str, parsed_data: dict[str, Any]) -> Any:
    """
    Return only the section of parsed_data relevant to this category.
    This prevents Gemini from getting confused by unrelated config sections.
    """
    if category == "LLM01:2025":
        # Prompt injection: system_prompt + any user-controlled inputs
        return {
            "system_prompt": parsed_data.get("system_prompt", ""),
            "tools": parsed_data.get("tools", []),
        }
    elif category == "LLM02:2025":
        # Sensitive info: everything (credentials can appear anywhere)
        return {
            "system_prompt": parsed_data.get("system_prompt", ""),
            "model_supply_chain": parsed_data.get("model_supply_chain", {}),
            "raw_content_preview": parsed_data.get("raw_content", "")[:3000],
        }
    elif category == "LLM03:2025":
        # Supply chain: model, plugins, adapters, sbom
        sc = parsed_data.get("model_supply_chain", {})
        if not sc:
            # Fall back to raw_content so Gemini still has something to reason about
            sc = {"raw_content": parsed_data.get("raw_content", "")[:3000]}
        return sc
    elif category == "LLM04:2025":
        # Data poisoning: pipeline, data_sources, training controls
        ti = parsed_data.get("training_ingestion", {})
        if not ti:
            ti = {"raw_content": parsed_data.get("raw_content", "")[:3000]}
        return ti
    elif category == "LLM05:2025":
        # Output handling: output handlers + raw code
        return {
            "output_handlers": parsed_data.get("output_handlers", []),
            "raw_content": parsed_data.get("raw_content", "")[:3000],
        }
    elif category == "LLM06:2025":
        # Excessive agency: tools + permissions
        return {
            "tools": parsed_data.get("tools", []),
            "permissions": parsed_data.get("permissions", []),
        }
    elif category == "LLM07:2025":
        # System prompt leakage: system prompt (where secrets live)
        return {
            "system_prompt": parsed_data.get("system_prompt", ""),
            "raw_content": parsed_data.get("raw_content", "")[:3000],
        }
    elif category == "LLM08:2025":
        # Vector/embedding: rag config
        rv = parsed_data.get("rag_vector", {})
        if not rv:
            rv = {"raw_content": parsed_data.get("raw_content", "")[:3000]}
        return rv
    elif category == "LLM09:2025":
        # Misinformation: policy misinfo signals + system prompt
        return {
            "system_prompt": parsed_data.get("system_prompt", ""),
            "policy_misinfo": parsed_data.get("policy_misinfo", {}),
            "raw_content": parsed_data.get("raw_content", "")[:2000],
        }
    elif category == "LLM10:2025":
        # Unbounded consumption: resource limits
        rl = parsed_data.get("resource_limits", {})
        if not rl:
            rl = {"raw_content": parsed_data.get("raw_content", "")[:3000]}
        return rl
    else:
        return parsed_data


# ---------------------------------------------------------------------------
# Individual scan functions — Original 4
# ---------------------------------------------------------------------------

async def scan_prompt_injection_llm(parsed_data: dict[str, Any]) -> dict:
    """LLM-powered scan for LLM01:2025 — Prompt Injection."""
    category = "LLM01:2025"
    focused = _get_focused_content(category, parsed_data)
    logger.info("SCAN %s | system_prompt_len=%d | tools=%d",
        category,
        len(str(focused.get("system_prompt", "") or "")),
        len(focused.get("tools", [])),
    )
    prompt = _build_prompt(
        category=category,
        category_name="Prompt Injection",
        task_description=(
            "Analyze the system prompt for prompt injection vulnerabilities. Look for: "
            "missing input delimiters, weak role definitions, user-controlled placeholders "
            "embedded in system instructions, lack of input validation, and susceptibility "
            "to direct or indirect injection attacks."
        ),
        focused_content=focused,
    )
    client = get_vertex_client()
    result = await client.analyze_with_llm(prompt)
    result["category"] = category
    result["detection_method"] = "llm_powered"
    return result


async def scan_sensitive_info_llm(parsed_data: dict[str, Any]) -> dict:
    """LLM-powered scan for LLM02:2025 — Sensitive Information Disclosure."""
    category = "LLM02:2025"
    focused = _get_focused_content(category, parsed_data)
    logger.info("SCAN %s | content_len=%d",
        category, len(str(focused)))
    prompt = _build_prompt(
        category=category,
        category_name="Sensitive Information Disclosure",
        task_description=(
            "Analyze for sensitive information disclosure risks. Look for: hardcoded credentials, "
            "API keys, PII in prompts or configs, overly permissive data access, training data "
            "memorization risks, and insufficient output filtering that could leak sensitive data."
        ),
        focused_content=focused,
    )
    client = get_vertex_client()
    result = await client.analyze_with_llm(prompt)
    result["category"] = category
    result["detection_method"] = "llm_powered"
    return result


async def scan_improper_output_llm(parsed_data: dict[str, Any]) -> dict:
    """LLM-powered scan for LLM05:2025 — Improper Output Handling."""
    category = "LLM05:2025"
    focused = _get_focused_content(category, parsed_data)
    logger.info("SCAN %s | output_handlers=%d | raw_len=%d",
        category,
        len(focused.get("output_handlers", [])),
        len(str(focused.get("raw_content", ""))),
    )
    prompt = _build_prompt(
        category=category,
        category_name="Improper Output Handling",
        task_description=(
            "Analyze for improper output handling vulnerabilities. Look for: LLM output passed "
            "directly to system calls, SQL queries, or HTML without sanitization; missing output "
            "validation; XSS risks; command injection via LLM output; and lack of output encoding."
        ),
        focused_content=focused,
    )
    client = get_vertex_client()
    result = await client.analyze_with_llm(prompt)
    result["category"] = category
    result["detection_method"] = "llm_powered"
    return result


async def scan_excessive_agency_llm(parsed_data: dict[str, Any]) -> dict:
    """LLM-powered scan for LLM06:2025 — Excessive Agency."""
    category = "LLM06:2025"
    focused = _get_focused_content(category, parsed_data)
    logger.info("SCAN %s | tools=%d | permissions=%d",
        category,
        len(focused.get("tools", [])),
        len(focused.get("permissions", [])),
    )
    prompt = _build_prompt(
        category=category,
        category_name="Excessive Agency",
        task_description=(
            "Analyze for excessive agency vulnerabilities. Look for: overly broad tool permissions, "
            "lack of principle of least privilege, missing human-in-the-loop controls for "
            "destructive actions, unrestricted autonomous decision-making, and missing safety "
            "constraints on agent actions."
        ),
        focused_content=focused,
    )
    client = get_vertex_client()
    result = await client.analyze_with_llm(prompt)
    result["category"] = category
    result["detection_method"] = "llm_powered"
    return result


# ---------------------------------------------------------------------------
# Individual scan functions — New 6
# ---------------------------------------------------------------------------

async def scan_supply_chain_llm(parsed_data: dict[str, Any]) -> dict:
    """LLM-powered scan for LLM03:2025 — Supply Chain."""
    category = "LLM03:2025"
    focused = _get_focused_content(category, parsed_data)
    logger.info("SCAN %s | supply_chain_keys=%s",
        category, list(focused.keys()) if isinstance(focused, dict) else "raw_str")
    prompt = _build_prompt(
        category=category,
        category_name="Supply Chain",
        task_description=(
            "Analyze the model/plugin/adapter configuration for supply chain security risks. "
            "Look for: third-party model references without version pinning (using 'latest' or '*'); "
            "allow_remote_code=true; checksum_verification=false or signature_verified=false; "
            "sbom.enabled=false or missing SBOM; plugins or adapters loaded from unverified "
            "external URLs or unknown sources; LoRA/fine-tuning adapters without signature checks."
        ),
        focused_content=focused,
    )
    client = get_vertex_client()
    result = await client.analyze_with_llm(prompt)
    result["category"] = category
    result["detection_method"] = "llm_powered"
    return result


async def scan_data_model_poisoning_llm(parsed_data: dict[str, Any]) -> dict:
    """LLM-powered scan for LLM04:2025 — Data and Model Poisoning."""
    category = "LLM04:2025"
    focused = _get_focused_content(category, parsed_data)
    logger.info("SCAN %s | ingestion_keys=%s",
        category, list(focused.keys()) if isinstance(focused, dict) else "raw_str")
    prompt = _build_prompt(
        category=category,
        category_name="Data and Model Poisoning",
        task_description=(
            "Analyze the training/ingestion/RAG pipeline configuration for data poisoning risks. "
            "Look for: auto_ingest_to_training_set=true without validation; data_validation=false; "
            "human_review_required=false; ingestion from public URLs or arbitrary user uploads; "
            "continuous fine-tuning pipeline with no anomaly detection; missing provenance tracking "
            "for training data sources; auto-approval of new data into model training or knowledge base."
        ),
        focused_content=focused,
    )
    client = get_vertex_client()
    result = await client.analyze_with_llm(prompt)
    result["category"] = category
    result["detection_method"] = "llm_powered"
    return result


async def scan_system_prompt_leakage_llm(parsed_data: dict[str, Any]) -> dict:
    """LLM-powered scan for LLM07:2025 — System Prompt Leakage."""
    category = "LLM07:2025"
    focused = _get_focused_content(category, parsed_data)
    sp_len = len(str(focused.get("system_prompt", "") or ""))
    logger.info("SCAN %s | system_prompt_len=%d", category, sp_len)
    prompt = _build_prompt(
        category=category,
        category_name="System Prompt Leakage",
        task_description=(
            "Analyze the system prompt for system prompt leakage risks. "
            "Look for: API keys, tokens, credentials, or secrets embedded directly in instructions; "
            "database connection strings or internal hostnames in the system prompt; "
            "role-based permission logic or access tiers described in plain language; "
            "business rules or transaction limits embedded explicitly; "
            "content filtering criteria described (reveals bypass vectors); "
            "instructions to 'keep this prompt confidential' without external enforcement; "
            "internal service names, IP addresses, or UNC paths revealed in the prompt."
        ),
        focused_content=focused,
    )
    client = get_vertex_client()
    result = await client.analyze_with_llm(prompt)
    result["category"] = category
    result["detection_method"] = "llm_powered"
    return result


async def scan_vector_embedding_llm(parsed_data: dict[str, Any]) -> dict:
    """LLM-powered scan for LLM08:2025 — Vector and Embedding Weaknesses."""
    category = "LLM08:2025"
    focused = _get_focused_content(category, parsed_data)
    logger.info("SCAN %s | rag_keys=%s",
        category, list(focused.keys()) if isinstance(focused, dict) else "raw_str")
    prompt = _build_prompt(
        category=category,
        category_name="Vector and Embedding Weaknesses",
        task_description=(
            "Analyze the RAG/vector store configuration for embedding security weaknesses. "
            "Look for: namespace_isolation=false in multi-tenant environments; "
            "allow_cross_namespace=true (cross-tenant data leakage risk); "
            "min_similarity_score=0.0 (retrieves anything, including injected content); "
            "allowed_domains=['*'] or auto_index_external_urls=true (arbitrary URL ingestion); "
            "sanitize_documents=false (allows hidden text/prompt injection in documents); "
            "no access controls or audit logging on retrieval."
        ),
        focused_content=focused,
    )
    client = get_vertex_client()
    result = await client.analyze_with_llm(prompt)
    result["category"] = category
    result["detection_method"] = "llm_powered"
    return result


async def scan_misinformation_llm(parsed_data: dict[str, Any]) -> dict:
    """LLM-powered scan for LLM09:2025 — Misinformation."""
    category = "LLM09:2025"
    focused = _get_focused_content(category, parsed_data)
    logger.info("SCAN %s | misinfo_signals=%s | sp_len=%d",
        category,
        list(focused.get("policy_misinfo", {}).keys()),
        len(str(focused.get("system_prompt", "") or "")),
    )
    prompt = _build_prompt(
        category=category,
        category_name="Misinformation",
        task_description=(
            "Analyze the agent configuration and system prompt for misinformation and hallucination risks. "
            "Look for: deployment in medical/legal/financial domains without RAG or grounding; "
            "instructions to 'answer confidently even if unsure' or 'provide definitive answers'; "
            "instructions to 'not mention uncertainty' or 'do not cite sources'; "
            "instructions to 'make the best guess' when unsure; "
            "no fact-checking or retrieval-augmented generation configured; "
            "no human-in-the-loop review for high-stakes outputs; "
            "code generation without mandatory security or correctness review."
        ),
        focused_content=focused,
    )
    client = get_vertex_client()
    result = await client.analyze_with_llm(prompt)
    result["category"] = category
    result["detection_method"] = "llm_powered"
    return result


async def scan_unbounded_consumption_llm(parsed_data: dict[str, Any]) -> dict:
    """LLM-powered scan for LLM10:2025 — Unbounded Consumption."""
    category = "LLM10:2025"
    focused = _get_focused_content(category, parsed_data)
    logger.info("SCAN %s | resource_limit_keys=%s",
        category, list(focused.keys()) if isinstance(focused, dict) else "raw_str")
    prompt = _build_prompt(
        category=category,
        category_name="Unbounded Consumption",
        task_description=(
            "Analyze the API/resource configuration for unbounded consumption risks. "
            "Look for: rate_limit_per_minute=0 or missing (no throttling); "
            "daily_quota=0 or missing (no spending cap); "
            "max_concurrent_requests=0 or missing (unlimited parallel requests); "
            "max_input_size_chars=0 or missing (no prompt size limit); "
            "timeout_seconds=0 or missing (no request timeout); "
            "max_retries set extremely high (e.g. 999999) enabling runaway retry loops; "
            "max_output_tokens extremely high without justification; "
            "batch_mode=true + allow_user_to_submit_jobs=true with no access controls."
        ),
        focused_content=focused,
    )
    client = get_vertex_client()
    result = await client.analyze_with_llm(prompt)
    result["category"] = category
    result["detection_method"] = "llm_powered"
    return result


# ---------------------------------------------------------------------------
# Orchestrator — 10 parallel scans
# ---------------------------------------------------------------------------

async def run_all_llm_scans(parsed_data: dict[str, Any]) -> list[dict]:
    """
    Run all 10 LLM scans in parallel using asyncio.gather().
    Each scan receives only its relevant focused content section.
    Returns only findings where vulnerabilities were found (found=True).
    """
    logger.info("===================================================")
    logger.info("=== STARTING LLM SCANS (10 parallel Gemini calls) ===")
    logger.info("===================================================")
    logger.info("  VERTEX_AI_PROJECT  : %s", os.environ.get("VERTEX_AI_PROJECT", "NOT SET"))
    logger.info("  VERTEX_AI_LOCATION : %s", os.environ.get("VERTEX_AI_LOCATION", "NOT SET"))
    logger.info("  Creds exists       : %s",
        os.path.exists(os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "")) )
    logger.info("  Parser fields present: supply_chain=%s | ingestion=%s | rag=%s | misinfo=%s | limits=%s",
        bool(parsed_data.get("model_supply_chain")),
        bool(parsed_data.get("training_ingestion")),
        bool(parsed_data.get("rag_vector")),
        bool(parsed_data.get("policy_misinfo")),
        bool(parsed_data.get("resource_limits")),
    )

    results = await asyncio.gather(
        scan_prompt_injection_llm(parsed_data),       # LLM01
        scan_sensitive_info_llm(parsed_data),         # LLM02
        scan_supply_chain_llm(parsed_data),           # LLM03
        scan_data_model_poisoning_llm(parsed_data),   # LLM04
        scan_improper_output_llm(parsed_data),        # LLM05
        scan_excessive_agency_llm(parsed_data),       # LLM06
        scan_system_prompt_leakage_llm(parsed_data),  # LLM07
        scan_vector_embedding_llm(parsed_data),       # LLM08
        scan_misinformation_llm(parsed_data),         # LLM09
        scan_unbounded_consumption_llm(parsed_data),  # LLM10
        return_exceptions=True,
    )


    findings: list[dict] = []
    categories = [
        "LLM01:2025", "LLM02:2025", "LLM03:2025", "LLM04:2025", "LLM05:2025",
        "LLM06:2025", "LLM07:2025", "LLM08:2025", "LLM09:2025", "LLM10:2025",
    ]

    raw_content = parsed_data.get("raw_content", "")

    for i, result in enumerate(results):
        cat = categories[i]
        if isinstance(result, Exception):
            logger.error("LLM scan for %s RAISED EXCEPTION: %s: %s",
                cat, type(result).__name__, result)
            continue
        
        found = result.get("found", False)
        logger.info("LLM scan %s => found=%s | severity=%s | confidence=%s",
            cat, found, result.get("severity", "?"), result.get("confidence", "?"))
        
        if found:
            # FR7: Add best-effort line number if evidence is present
            if not result.get("line_number") and result.get("evidence"):
                # Try first evidence item
                first_evidence = result["evidence"][0]
                # Use get_line_number from parser
                line = get_line_number(raw_content, first_evidence)
                if line:
                    result["line_number"] = line
            
            findings.append(result)

    logger.info("===================================================")
    logger.info("=== LLM SCANS COMPLETE: %d / 10 categories found vulnerabilities ===", len(findings))
    logger.info("===================================================")
    return findings
