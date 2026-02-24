# backend/ai_analysis_app/preprocessing/schema.py

from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class VulnerabilityRecord:
    """
    Standardized Schema for Security Findings.
    Acts as the single source of truth for all parsers (PDF, CSV, DOCX).
    """
    source_file: str = ""
    
    # Identity
    vuln_id: str = ""       # Plugin ID, QID, etc.
    vuln_name: str = ""     # Title of the finding
    
    # Asset Info
    asset_id: str = "Unknown_Device"  # IP, Hostname, or "Global"
    hostname: str = ""
    os: str = ""
    branch: str = ""
    
    # Risk Assessment
    severity: float = 0.0   # Normalized 0.0 - 10.0
    risk_level_str: str = "Info" # Original string (High, Med, etc.)
    cvss_base_score: float = 0.0
    likelihood: str = ""    # Likelihood of exploitation
    ease: str = ""          # Ease of Exploitation
    
    # Technical Details
    cve_id: List[str] = field(default_factory=list)
    port: str = ""
    protocol: str = ""
    
    # Context & Remediation
    # 🚨 CRITICAL FIX: Ensure 'description' exists and defaults to empty string
    description: str = ""   
    solution: str = ""
    proof: str = ""         # Legacy field, kept for compatibility
    status: str = ""
    references: str = ""
    category: str = ""
    
    # Granular Extraction Fields (For customized RAG retrieval)
    impact: str = ""
    affected_url: str = "" # Specific URL if different from asset_id
    raw_evidence: str = "" # The literal proof/steps
    owasp_link: str = ""   # Specific reference link

    def __post_init__(self):
        # Ensure lists are lists (handling some edge cases)
        if self.cve_id is None:
            self.cve_id = []
        # Ensure description is never None to prevent += errors
        if self.description is None:
            self.description = ""
