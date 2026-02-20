"""
Risk scoring engine.

Formula (from PRD V3 Section 6 FR6):
    Score = Σ (Base Weight × Severity Multiplier × Confidence Factor)
    Capped at 100.

Risk levels:
    0–25:   Low
    26–50:  Medium
    51–75:  High
    76–100: Critical
"""

from typing import Any

from app.models.scan_response import VulnerabilityFinding

# Base weights per OWASP category (PRD Section 6 FR6)
# New categories added for all 10 OWASP LLM 2025 entries.
# Score is capped at 100 by min() in calculate_risk_score().
CATEGORY_WEIGHTS: dict[str, int] = {
    # Original 4
    "LLM01:2025": 35,   # Prompt Injection — highest impact
    "LLM02:2025": 30,   # Sensitive Information Disclosure
    "LLM06:2025": 20,   # Excessive Agency
    "LLM05:2025": 15,   # Improper Output Handling
    # New 6
    "LLM04:2025": 25,   # Data and Model Poisoning — high integrity risk
    "LLM07:2025": 22,   # System Prompt Leakage — credentials exposure risk
    "LLM03:2025": 20,   # Supply Chain
    "LLM08:2025": 18,   # Vector and Embedding Weaknesses
    "LLM09:2025": 15,   # Misinformation
    "LLM10:2025": 12,   # Unbounded Consumption
}

# Severity multipliers (PRD Section 6 FR6)
SEVERITY_MULTIPLIERS: dict[str, float] = {
    "Critical": 1.0,
    "High":     1.0,    # Treat High same as Critical for scoring
    "Medium":   0.6,
    "Low":      0.3,
    "None":     0.0,
}

# Risk level thresholds (PRD Section 6 FR6)
_THRESHOLDS = [
    (76, "Critical"),
    (51, "High"),
    (26, "Medium"),
    (0,  "Low"),
]


def _get_risk_level(score: int) -> str:
    for threshold, level in _THRESHOLDS:
        if score >= threshold:
            return level
    return "Low"


def calculate_risk_score(findings: list[VulnerabilityFinding]) -> dict[str, Any]:
    """
    Calculate the overall risk score and return a full breakdown dict.

    Returns:
        {
            risk_score: int (0-100),
            risk_level: str,
            breakdown_by_category: dict[str, float],
            total_findings: int,
            critical_severity_count: int,
            high_severity_count: int,
            medium_severity_count: int,
            low_severity_count: int,
            summary: str,
        }
    """
    if not findings:
        return {
            "risk_score": 0,
            "risk_level": "Low",
            "breakdown_by_category": {},
            "total_findings": 0,
            "critical_severity_count": 0,
            "high_severity_count": 0,
            "medium_severity_count": 0,
            "low_severity_count": 0,
            "summary": "No vulnerabilities detected. Configuration appears secure.",
        }

    total_score: float = 0.0
    breakdown: dict[str, float] = {}
    severity_counts: dict[str, int] = {
        "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 0
    }

    for finding in findings:
        category  = finding.category
        severity  = finding.severity
        confidence = finding.confidence  # already 0.0–1.0

        # FR6: Confidence Bucketing
        if confidence >= 0.90:
            conf_factor = 1.0
        elif confidence >= 0.70:
            conf_factor = 0.9
        elif confidence >= 0.50:
            conf_factor = 0.7
        else:
            conf_factor = 0.5

        base_weight   = CATEGORY_WEIGHTS.get(category, 10)
        severity_mult = SEVERITY_MULTIPLIERS.get(severity, 0.5)
        # Apply bucketed confidence factor instead of raw float
        contribution  = base_weight * severity_mult * conf_factor

        total_score += contribution
        breakdown[category] = round(breakdown.get(category, 0.0) + contribution, 2)

        if severity in severity_counts:
            severity_counts[severity] += 1

    risk_score = min(int(round(total_score)), 100)
    risk_level = _get_risk_level(risk_score)

    # Build human-readable summary
    critical_high = severity_counts["Critical"] + severity_counts["High"]
    if critical_high > 0:
        summary = (
            f"{critical_high} critical/high severity {'vulnerability' if critical_high == 1 else 'vulnerabilities'} "
            f"detected across {len(breakdown)} OWASP {'category' if len(breakdown) == 1 else 'categories'}. "
            f"Immediate remediation required."
        )
    elif severity_counts["Medium"] > 0:
        summary = (
            f"{severity_counts['Medium']} medium severity "
            f"{'vulnerability' if severity_counts['Medium'] == 1 else 'vulnerabilities'} detected. "
            f"Review and remediate before production deployment."
        )
    else:
        summary = (
            f"{len(findings)} low severity {'finding' if len(findings) == 1 else 'findings'} detected. "
            f"Consider addressing as part of security hardening."
        )

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "breakdown_by_category": breakdown,
        "total_findings": len(findings),
        "critical_severity_count": severity_counts["Critical"],
        "high_severity_count": severity_counts["High"],
        "medium_severity_count": severity_counts["Medium"],
        "low_severity_count": severity_counts["Low"],
        "summary": summary,
    }
