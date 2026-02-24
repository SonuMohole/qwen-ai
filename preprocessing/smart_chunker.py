# backend/preprocessing/smart_chunker.py

import pandas as pd
import os
import re
from typing import List, Tuple
from .schema import VulnerabilityRecord

# ==============================================================================
# 🧠 CONFIGURATION & UTILITIES
# ==============================================================================

MAX_CHUNK_SIZE_CSV = 1500
MAX_CHUNK_SIZE_PDF = 1500

def get_risk_label(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score > 0.0: return "LOW"
    return "INFO"

def normalize_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Standardizes the DataFrame derived from VulnerabilityRecords."""
    if 'vuln_name' in df.columns:
        df['title'] = df['vuln_name'].fillna('Unknown Issue')
    else:
        df['title'] = 'Unknown Issue'

    if 'asset_id' in df.columns:
        df['asset'] = df['asset_id'].fillna('Unknown_Device')
    else:
        df['asset'] = 'Unknown_Device'
        
    if 'severity' in df.columns:
        df['severity_score'] = pd.to_numeric(df['severity'], errors='coerce').fillna(0.0)
    else:
        df['severity_score'] = 0.0

    if 'risk_level_str' not in df.columns:
         df['risk_level_str'] = 'Info'
    
    def derive_score(row):
        score = float(row.get('severity_score', 0.0))
        if score > 0.0: return score
        
        label = str(row.get('risk_level_str', '')).upper()
        if 'CRITICAL' in label: return 10.0
        if 'HIGH' in label: return 8.0
        if 'MEDIUM' in label or 'MODERATE' in label: return 5.0
        if 'LOW' in label: return 2.0
        return 0.0

    df['severity_score'] = df.apply(derive_score, axis=1)
    return df

def recursive_split_markdown(text: str, max_chars: int = 1500) -> List[str]:
    """Intelligently splits markdown text into chunks."""
    if len(text) <= max_chars:
        return [text]
        
    chunks = []
    # Split by double newlines (paragraphs)
    paragraphs = re.split(r'\n\s*\n', text)
    
    current_chunk = []
    current_len = 0
    
    for p in paragraphs:
        p_len = len(p)
        if current_len + p_len > max_chars:
            if current_chunk:
                chunks.append("\n\n".join(current_chunk))
                current_chunk = []
                current_len = 0
            if p_len > max_chars:
                for i in range(0, p_len, max_chars):
                    chunks.append(p[i:i+max_chars])
            else:
                current_chunk.append(p)
                current_len += p_len
        else:
            current_chunk.append(p)
            current_len += p_len
            
    if current_chunk:
        chunks.append("\n\n".join(current_chunk))
    return chunks

# ==============================================================================
# 📄 STRATEGY A: DOCUMENT (PDF/DOCX) - Semantic Chunking
# ==============================================================================

def generate_finding_chunk(r: dict) -> str:
    """Creates a high-fidelity chunk for a specific vulnerability finding."""
    title = r.get('title', 'Unknown Issue')
    severity = r.get('severity_score', 0)
    label = get_risk_label(severity)
    icon = "🔴" if severity >= 7 else "🟠" if severity >= 4 else "🔵"
    
    text = f"# {icon} {title} ({label})\n\n"
    
    display_severity = r.get('risk_level_str')
    if not display_severity or display_severity == "Info":
        display_severity = f"{severity} ({label})"
        
    text += f"**Severity**: {display_severity}\n"
    text += f"**Asset**: {r.get('asset', 'N/A')}\n"
    
    # 🎯 Explicitly include Affected URL for retrieval
    if r.get('affected_url'):
        text += f"**Affected URL**: {r.get('affected_url')}\n"
    
    # 🎯 New Fields for Better Precision
    if r.get('cvss_base_score'):
        text += f"**CVSS Score**: {r.get('cvss_base_score')}\n"
        
    if r.get('likelihood'):
        text += f"**Likelihood**: {r.get('likelihood')}\n"
        
    if r.get('impact'):
        text += f"**Impact**: {r.get('impact')}\n"
    
    cves = r.get('cve_id')
    if cves and isinstance(cves, list) and len(cves) > 0:
        text += f"**Dimensions**: {', '.join(cves)}\n"
        
    # 🔗 Explicitly include OWASP Link
    if r.get('owasp_link'):
        text += f"**OWASP Reference**: {r.get('owasp_link')}\n"
        
    text += "\n## Description\n"
    text += str(r.get('description', 'N/A')) + "\n"
    
    # Ensure Impact is visible if not in description (though cleaner puts it there usually)
    # If cleaner puts it in description, we assume it's there. 
    # But let's be safe for Executive Summary generation logic.
    
    if r.get('solution'):
        text += "\n## Recommendation\n"
        text += str(r.get('solution', '')) + "\n"
        
    if r.get('proof') or r.get('raw_evidence'):
        text += "\n## Evidence\n"
        ev = r.get('raw_evidence') if r.get('raw_evidence') else r.get('proof', '')
        text += str(ev) + "\n"
        
    return text

def generate_report_summary(df: pd.DataFrame) -> str:
    """Generates a synthetic summary chunk."""
    # Filter out purely informational records from the stats
    # Heuristic: Risk Label 'INFO' or vuln_id null/empty
    finding_df = df[df['severity_score'] > 0.1]
    
    total = len(finding_df)
    severity_counts = finding_df['severity_score'].apply(get_risk_label).value_counts()
    
    # 1. Stats and Overview (Answering "Summarize this report")
    text = "# 📊 REPORT OVERVIEW & STATISTICS\n\n"
    text += f"**Total Findings**: {total}\n"
    text += "**Risk Breakdown**:\n"
    for label, count in severity_counts.items():
        icon = "🔴" if label in ["CRITICAL", "HIGH"] else "🟠" if label == "MEDIUM" else "🔵"
        text += f"- {icon} {label}: {count}\n"
        
    # 2. Top Risky Assets (Answering "Which specific IP addresses...")
    text += "\n## Top Risky Assets\n"
    if 'asset' in finding_df.columns:
        # Use finding_df here to ignore Info rows
        asset_stats = finding_df.groupby('asset')['severity_score'].agg(['count', 'max', 'sum'])
        asset_stats = asset_stats.sort_values(by='sum', ascending=False).head(5)
        
        for asset, stats in asset_stats.iterrows():
            risk_label = get_risk_label(stats['max'])
            count = int(stats['count'])
            text += f"- **{asset}**: {count} issues (Max Risk: {risk_label})\n"
            
    # 3. CVE Index (Answering "Resolve CVE-2023-XXXX")
    text += "\n## CVE Index\n"
    all_cves = set()
    for ids in finding_df['cve_id'].dropna():
        if isinstance(ids, list):
            all_cves.update(ids)
        elif isinstance(ids, str):
            all_cves.add(ids)
            
    valid_cves = sorted([c for c in all_cves if c and len(c) > 3])
    if valid_cves:
        text += ", ".join(valid_cves) + "\n"
    else:
        text += "No CVEs identified.\n"
        
    return text

def generate_remediation_plan(df: pd.DataFrame) -> str:
    """Generates a Consolidated Remediation Plan for Developers."""
    critical_df = df[df['severity_score'] >= 7.0]
    
    if critical_df.empty:
        return "# ✅ REMEDIATION ACTION PLAN\n\nNo Critical or High severity issues were found."

    text = "# 🛠️ PRIORITY REMEDIATION ACTION PLAN\n\n"
    text += "This checklist focuses on High/Critical vulnerabilities requiring immediate attention.\n\n"
    
    for idx, r in critical_df.sort_values(by='severity_score', ascending=False).iterrows():
        title = r.get('title', 'Issue')
        label = get_risk_label(r.get('severity_score', 0))
        solution = str(r.get('solution', 'No specific remediation provided.')).replace("\n", " ").strip()
        asset = r.get('asset', 'Unknown Asset')
        
        text += f"### [ ] Fix {title} ({label})\n"
        text += f"**Target**: {asset}\n"
        text += f"**Action**: {solution[:300]}...\n" 
        text += f"**Ref ID**: {r.get('vuln_id')}\n\n"
        
    return text

def generate_quick_wins(df: pd.DataFrame) -> str:
    """Generates "Low hanging fruit" list (Low/Medium issues)."""
    # Filter for Medium/Low issues
    quick_wins = df[(df['severity_score'] >= 2.0) & (df['severity_score'] < 7.0)]
    
    if quick_wins.empty:
        return "# ⚡ QUICK WINS & LOW HANGING FRUIT\n\nNo low/medium severity issues identified."

    text = "# ⚡ QUICK WINS & LOW HANGING FRUIT\n\n"
    text += "These issues are often configuration tweaks or minor patches that improve security posture quickly.\n\n"
    
    for idx, r in quick_wins.sort_values(by='severity_score', ascending=False).head(10).iterrows():
        title = r.get('title', 'Issue')
        label = get_risk_label(r.get('severity_score', 0))
        solution = str(r.get('solution', 'No specific remediation provided.')).replace("\n", " ").strip()
        
        text += f"- **{title}** ({label}): {solution[:150]}...\n"
        
    return text

def generate_executive_risk(df: pd.DataFrame) -> str:
    """Generates a Business Impact Summary & Verdict."""
    high_risks = df[df['severity_score'] >= 7.0]
    
    # Verdict Logic (Answering "Can we go live?")
    if high_risks.empty:
        verdict = "✅ **VERDICT: GO LIVE RECOMMENDED**\nNo Critical or High severity vulnerabilities were detected. The application security posture is strong."
    else:
        verdict = "🚫 **VERDICT: GO LIVE NOT RECOMMENDED**\nThe presence of Critical/High vulnerabilities poses significant business risk. Remediation is required before production deployment."

    text = "# 🛡️ EXECUTIVE RISK SUMMARY & BUSINESS IMPACT\n\n"
    text += f"{verdict}\n\n"
    
    if high_risks.empty:
         text += "No critical business risks identified."
         return text
         
    text += "## Critical Business Risks\n"
    text += "The following vulnerabilities could lead to data breach, financial loss, or reputational damage:\n\n"
    
    for idx, r in high_risks.sort_values(by='severity_score', ascending=False).iterrows():
        title = r.get('title', 'Issue')
        
        # Use dedicated Impact field if available, otherwise fallback to description heuristic
        impact = str(r.get('impact', ''))
        if not impact or len(impact) < 5:
             desc = str(r.get('description', ''))
             impact = desc.split('\n')[0][:250]
        
        text += f"- **{title}**\n"
        text += f"  - **Business Impact**: {impact}...\n"
        text += f"  - **Risk Level**: {get_risk_label(r.get('severity_score', 0))}\n\n"
        
    return text

def chunk_strategy_document(df: pd.DataFrame) -> List[Tuple[str, dict]]:
    print("  - [Chunker] 📑 Applying DOCUMENT Strategy (Semantic Chunking)")
    chunks = []
    
    # 0.1 High Level Summaries
    chunks.append((generate_report_summary(df), {
        "asset_id": "REPORT_SUMMARY",
        "chunk_type": "summary",
        "risk_label": "INFO"
    }))
    
    # 0.2 Remediation Plan (Developers)
    chunks.append((generate_remediation_plan(df), {
        "asset_id": "REPORT_PLAN",
        "chunk_type": "remediation_plan",
        "risk_label": "CRITICAL"
    }))

    # 0.3 Executive Risk (Board/Manager)
    chunks.append((generate_executive_risk(df), {
        "asset_id": "REPORT_RISK",
        "chunk_type": "executive_risk",
        "risk_label": "HIGH"
    }))

    # 0.4 Quick Wins (DevOps/Admins)
    chunks.append((generate_quick_wins(df), {
        "asset_id": "REPORT_QUICK_WINS",
        "chunk_type": "quick_wins",
        "risk_label": "LOW"
    }))
    
    records = df.to_dict('records')
    
    for r in records:
        asset_id = r.get('asset', '')
        vuln_id = str(r.get('vuln_id', ''))
        vuln_name = r.get('title', '')
        description = r.get('description', '')
        
        # 1. 🛡️ VULNERABILITY FINDING (High Fidelity)
        if vuln_id and vuln_id.startswith('F-'):
            txt = generate_finding_chunk(r)
            cve_ids = r.get('cve_id', [])
            cve_str = ",".join(cve_ids) if isinstance(cve_ids, list) else str(cve_ids) if cve_ids else ""
            
            meta = {
                "asset_id": asset_id if asset_id else "Global",
                "vuln_id": vuln_id,
                "cve_id": cve_str,
                "chunk_type": "finding",
                "risk_label": get_risk_label(r.get('severity_score', 0))
            }
            chunks.append((txt, meta))
            
        # 2. 📋 INFO OR NARRATIVE (Split if needed)
        elif asset_id in ["REPORT_METADATA", "REPORT_NARRATIVE"]:
            # Special Tagging for Scope and Compliance
            ctype = "info"
            if "Scope" in vuln_name: ctype = "scope"
            elif "Compliance" in vuln_name: ctype = "compliance"
            elif "Team" in vuln_name: ctype = "team"
            elif asset_id == "REPORT_NARRATIVE": ctype = "narrative"

            record_chunks = recursive_split_markdown(description, MAX_CHUNK_SIZE_PDF)
            
            for i, chunk_text in enumerate(record_chunks):
                header_prefix = f"# {vuln_name}"
                if len(record_chunks) > 1: header_prefix += f" (Part {i+1})"
                
                final_txt = f"{header_prefix}\n\n{chunk_text}"
                
                meta = {
                    "asset_id": asset_id,
                    "chunk_type": ctype,
                    "risk_label": "INFO",
                    "part": i + 1
                }
                chunks.append((final_txt, meta))
            
        else:
            pass 
            
    return chunks

# ==============================================================================
# 📊 STRATEGY B: TABULAR (CSV/EXCEL)
# ==============================================================================
def generate_dense_chunk(records: List[dict], asset_id: str, part: int) -> str:
    """Creates a 'List' style chunk for CSVs."""
    text = f"# Security Report: {asset_id} (Part {part})\n"
    text += f"**Findings:** {len(records)} | **Highest Risk:** {get_risk_label(records[0].get('severity_score', 0))}\n"
    text += "-" * 50 + "\n"

    for i, r in enumerate(records, 1):
        sev = r.get('severity_score', 0)
        label = get_risk_label(sev)
        icon = "🔴" if sev >= 7 else "⚪"
        title = str(r.get('title', 'Issue')).replace("\n", " ")
        cves = str(r.get('cve_id', ''))
        
        entry = f"{i}. {icon} [{label}] {title}"
        if cves and len(cves) > 2 and cves != "[]": entry += f" (IDs: {cves})"
        entry += "\n"
        desc = str(r.get('description', ''))[:100].replace("\n", " ")
        if len(desc) > 5: entry += f"   Context: {desc}...\n"
        text += entry + "\n"
        
    return text

def chunk_strategy_tabular(df: pd.DataFrame) -> List[Tuple[str, dict]]:
    print("  - [Chunker] 📊 Applying TABULAR Strategy")
    chunks = []
    grouped = df.groupby('asset')
    
    for asset_id, group in grouped:
        records = group.to_dict('records')
        records = sorted(records, key=lambda x: x.get('severity_score', 0), reverse=True)
        current_page = []
        current_len = 0
        part = 1
        
        for rec in records:
            rec_size = 300 
            if current_len + rec_size > MAX_CHUNK_SIZE_CSV and current_page:
                txt = generate_dense_chunk(current_page, str(asset_id), part)
                meta = {
                    "asset_id": str(asset_id),
                    "chunk_type": "asset_list",
                    "risk_label": get_risk_label(group['severity_score'].max()),
                    "part": part
                }
                chunks.append((txt, meta))
                current_page = []
                current_len = 0
                part += 1
            current_page.append(rec)
            current_len += rec_size
            
        if current_page:
            txt = generate_dense_chunk(current_page, str(asset_id), part)
            meta = {
                "asset_id": str(asset_id),
                "chunk_type": "asset_list",
                "risk_label": get_risk_label(group['severity_score'].max()),
                "part": part
            }
            chunks.append((txt, meta))
            
    return chunks

# ==============================================================================
# 🔌 MAIN ENTRY POINT
# ==============================================================================

def smart_chunk_records(records: List[VulnerabilityRecord]) -> List[Tuple[str, dict]]:
    if not records:
        print("  ⚠️  [Chunker] No records provided")
        return []
        
    filename = records[0].source_file if records[0].source_file else "unknown.csv"
    ext = os.path.splitext(filename)[1].lower()
    data = [vars(r) for r in records]
    df = pd.DataFrame(data)
    
    print(f"\\n{'='*60}")
    print(f"  🛡️  SMART CHUNKER v5.1 (Specialized)")
    print(f"{'='*60}")
    
    norm_df = normalize_dataframe(df)
    
    if ext in ['.pdf', '.docx', '.doc']:
        chunks = chunk_strategy_document(norm_df)
    else:
        chunks = chunk_strategy_tabular(norm_df)
    
    print(f"  📦 Generated {len(chunks)} optimized chunks")
    print(f"{'='*60}\\n")
    return chunks
