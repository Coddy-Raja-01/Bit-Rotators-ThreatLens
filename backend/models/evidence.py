from __future__ import annotations
from typing import Any, Literal, List, Dict, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field, ConfigDict

SeverityLevel = Literal["info", "low", "medium", "high", "critical"]
RiskClassification = Literal[
    "Low Risk",
    "Suspicious",
    "High Risk",
    "Confirmed Malicious",
    "Inconclusive"
]


class Finding(BaseModel):
    """Standardized atomic finding emitted by every ThreatLens scanner."""

    model_config = ConfigDict(extra="allow")

    id: str = Field(..., description="Unique finding code, e.g. TLS-01, URL-02, INTEL-01")
    title: str = Field(..., description="Short descriptive finding title")
    source: str = Field(default="ThreatLens", description="Authoritative origin, e.g. crt.sh, URLhaus, local heuristic")
    observed_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="UTC ISO timestamp when the finding was recorded"
    )
    evidence: Any = Field(default_factory=dict, description="Structured evidence backing the finding")
    impact: str = Field(default="", description="Potential security impact of the finding")
    severity: SeverityLevel = Field(default="info", description="Finding severity level")
    confidence: float = Field(default=0.85, ge=0.0, le=1.0, description="Confidence score 0.0 - 1.0")
    recommendation: str = Field(default="", description="Recommended action or remediation")
    limitations: str = Field(default="", description="Known limitations or caveats for this check")
    issue: Optional[str] = Field(default=None, description="Human-facing issue statement for website-security findings")
    module: Optional[str] = Field(default=None, description="Scanner module, e.g. certificate, lookalike, content")
    technical_evidence: Any = Field(default_factory=dict, description="Legacy compatibility alias for the structured evidence payload")
    potential_impact: Optional[str] = None
    remediation: Optional[str] = None
    timestamp: Optional[str] = Field(default=None, description="Legacy timestamp compatibility field")

    @classmethod
    def from_legacy(cls, payload: Any) -> "Finding":
        if isinstance(payload, cls):
            return payload
        if not isinstance(payload, dict):
            raise TypeError(f"Finding payload must be a dict, got {type(payload).__name__}")

        normalized = dict(payload)
        normalized.setdefault("source", "ThreatLens")
        normalized.setdefault("title", normalized.get("issue") or normalized.get("title") or "Unspecified finding")
        normalized.setdefault("issue", normalized.get("title"))
        normalized.setdefault("evidence", normalized.get("technical_evidence") or normalized.get("evidence") or {})
        normalized.setdefault("technical_evidence", normalized.get("evidence"))
        normalized.setdefault("impact", normalized.get("potential_impact") or normalized.get("impact") or "")
        normalized.setdefault("potential_impact", normalized.get("impact"))
        normalized.setdefault("recommendation", normalized.get("remediation") or normalized.get("recommendation") or "")
        normalized.setdefault("remediation", normalized.get("recommendation"))
        normalized.setdefault("limitations", normalized.get("limitations") or "")
        if not normalized.get("observed_at"):
            normalized["observed_at"] = normalized.get("timestamp") or datetime.now(timezone.utc).isoformat()
        normalized.setdefault("timestamp", normalized.get("observed_at"))
        normalized["severity"] = _normalize_severity(normalized.get("severity"))
        return cls(**normalized)

    def to_dict(self) -> dict:
        data = self.model_dump(exclude_none=True)
        data.setdefault("issue", self.title)
        data.setdefault("technical_evidence", self.evidence)
        data.setdefault("observed_at", self.timestamp or self.observed_at)
        if not data.get("source"):
            data["source"] = "ThreatLens"
        return data


def _normalize_severity(value: Any) -> SeverityLevel:
    if value is None:
        return "info"
    normalized = str(value).strip().lower()
    if normalized in {"critical", "crit"}:
        return "critical"
    if normalized in {"high", "warning"}:
        return "high"
    if normalized in {"medium", "moderate"}:
        return "medium"
    if normalized in {"low", "minor"}:
        return "low"
    if normalized in {"safe", "ok", "pass"}:
        return "info"
    return "info"


class CheckExecutionStatus(BaseModel):
    name: str
    status: Literal["completed", "failed", "skipped", "not_applicable"]
    details: str = ""
    duration_ms: Optional[int] = None


class EvidenceCoverage(BaseModel):
    """
    Tracks which modules and checks ran, passed, failed, or were skipped.
    """
    total_checks: int = 0
    executed_checks: int = 0
    skipped_checks: int = 0
    failed_checks: int = 0
    checks: List[CheckExecutionStatus] = Field(default_factory=list)


class RiskAssessment(BaseModel):
    """Unified 5-class risk assessment produced by the ThreatLens scoring engine."""

    report_id: str = Field(..., description="Stable unique report identifier (UUID4)")
    target_url: str
    normalized_url: str
    domain: str
    classification: RiskClassification
    score: int = Field(ge=0, le=100, description="Supplementary 0-100 risk index")
    disclaimer: str = Field(
        default="Absence of known threats is not proof of safety. ThreatLens provides evidence-based assessment at the time of inspection.",
        description="Mandatory disclaimer for all classifications"
    )
    indicators: List[str] = Field(default_factory=list, description="Primary flags that contributed to the classification")
    findings: List[Finding] = Field(default_factory=list, description="Structured list of all atomic findings")
    per_finding_sources: List[str] = Field(default_factory=list, description="Unique data sources referenced by findings")
    evidence_coverage: Dict[str, Any] = Field(default_factory=dict, description="Coverage metadata for the assessment")
    analysis_timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Overall confidence for classification")
    recommended_actions: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    elapsed_ms: int = 0
    threat_indicators: List[str] = Field(default_factory=list, description="Backward-compatible alias for indicators")
    evidence_sources: List[str] = Field(default_factory=list, description="Backward-compatible alias for per_finding_sources")
    coverage: Dict[str, Any] = Field(default_factory=dict, description="Backward-compatible alias for evidence_coverage")

    def to_dict(self) -> dict:
        data = self.model_dump(exclude_none=True)
        data.setdefault("indicators", data.get("threat_indicators", []))
        data.setdefault("per_finding_sources", data.get("evidence_sources", []))
        data.setdefault("evidence_coverage", data.get("coverage", {}))
        return data

