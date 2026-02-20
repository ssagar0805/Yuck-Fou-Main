"""
Pydantic response models for the scan API.
Matches the schema defined in PRD V3 Section 7.
"""

from typing import List, Literal, Optional
from pydantic import BaseModel, Field


OWASPCategory = Literal[
    "LLM01:2025", "LLM02:2025", "LLM03:2025", "LLM04:2025",
    "LLM05:2025", "LLM06:2025", "LLM07:2025", "LLM08:2025",
    "LLM09:2025", "LLM10:2025",
]
SeverityLevel = Literal["Critical", "High", "Medium", "Low", "None"]


class VulnerabilityFinding(BaseModel):
    """A single vulnerability finding from the scan."""

    category: OWASPCategory
    severity: SeverityLevel
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score 0.0–1.0")
    evidence: List[str] = Field(default_factory=list, description="Exact quotes or line refs")
    description: str = Field(..., description="Explanation of the vulnerability")
    remediation: str = Field(..., description="Specific fix recommendation")
    detection_method: Literal["rule_based", "llm_powered", "hybrid"] = "hybrid"
    attack_scenario: str = ""
    line_number: int | None = Field(None, description="Line number (1-indexed)")
    source_location: str | None = Field(None, description="JSON path or context location")
    owasp_reference: str | None = Field(None, description="Official OWASP citation")


class ScanResponse(BaseModel):
    """Complete response returned by the /api/scan endpoint."""

    # Core fields
    scan_id: str = Field(..., description="Unique scan identifier")
    timestamp: str = Field(..., description="ISO 8601 timestamp")
    file_name: str = ""
    file_type: str = ""

    # Risk assessment
    risk_score: int = Field(..., ge=0, le=100, description="Overall risk score 0–100")
    risk_level: Literal["Low", "Medium", "High", "Critical"] = "Low"
    summary: str = ""

    # Findings
    findings: List[VulnerabilityFinding] = Field(default_factory=list)

    # Scoring breakdown
    breakdown_by_category: dict = Field(default_factory=dict)
    total_findings: int = 0
    critical_severity_count: int = 0
    high_severity_count: int = 0
    medium_severity_count: int = 0
    low_severity_count: int = 0

    # Performance
    scan_duration: float = Field(..., description="Scan duration in seconds")
    timings: dict = Field(default_factory=dict, description="Detailed scan timings")
    pdf_url: str | None = Field(None, description="URL to download PDF report")

class MultiFilesResponse(BaseModel):
    """Response model for multi-file upload scan."""
    files: List[ScanResponse] = Field(..., description="List of individual scan results")
    overall: dict = Field(..., description="Aggregated risk metrics")
    processed_at: str = Field(..., description="ISO 8601 timestamp")
    pdf_url: str | None = Field(None, description="URL to download consolidated PDF report")
