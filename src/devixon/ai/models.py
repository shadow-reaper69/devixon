"""
Pydantic models for structured AI analyst responses.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class AIReconSummary(BaseModel):
    summary: str = Field(description="High-level attack surface summary.")
    discovered_hosts_count: int
    critical_attack_vectors: List[str] = Field(default_factory=list)
    recommended_focus_areas: List[str] = Field(default_factory=list)
    limitations: str = Field(description="Known blind spots or limitations in available data.")


class AIFindingAnalysis(BaseModel):
    title: str
    category: str
    verified_evidence_summary: str
    missing_evidence: List[str] = Field(default_factory=list)
    confidence: str = Field(description="CONFIRMED, LIKELY, SUSPECTED, or INFORMATIONAL")
    reasoning_summary: str = Field(description="Concise evidence-based reasoning without hidden chain-of-thought.")
    potential_impact: str
    suggested_manual_validation: List[str] = Field(default_factory=list)
    remediation_recommendation: str
    references: List[str] = Field(default_factory=list)


class AIRemediationPlan(BaseModel):
    issue_title: str
    immediate_mitigation: str
    strategic_fix: str
    configuration_guidance: Optional[str] = None
    verification_test: str
