# backend/ai_analysis_app/preprocessing/cleaner_pdf.py

import re
import pymupdf4llm
from typing import List, Optional, Dict
from .schema import VulnerabilityRecord

# ==============================================================================
# 🧠 LAZY MODEL LOADING (Prevents Crash Loops)
# ==============================================================================
_NER_MODEL_INSTANCE = None

def get_ner_model():
    """
    Singleton pattern to load GLiNER only when actually needed.
    Prevents the server from loading the model on every import/restart.
    """
    global _NER_MODEL_INSTANCE
    
    if _NER_MODEL_INSTANCE is None:
        print("⏳ Loading Cyber-NER Model (GLiNER)... [Lazy Init]")
        try:
            from gliner import GLiNER
            _NER_MODEL_INSTANCE = GLiNER.from_pretrained("urchade/gliner_small-v2.1")
            print("✅ GLiNER Loaded Successfully.")
        except Exception as e:
            print(f"⚠️ GLiNER load failed: {e}. Narrative enrichment disabled.")
            _NER_MODEL_INSTANCE = False # Mark as failed so we don't retry endlessly
            
    return _NER_MODEL_INSTANCE

# Define labels we specifically care about in text
CYBER_LABELS = ["cve_id", "ip_address", "malware", "threat_actor", "severity_score"]

# ==============================================================================
# 🧠 TABLE HEADER INTELLIGENCE
# ==============================================================================

def identify_table_type(header_row: str) -> str:
    """Analyzes the header row to determine what KIND of table this is."""
    h = header_row.lower()
    
    # 1. TEAM / STAKEHOLDERS
    if "name" in h and ("responsibility" in h or "role" in h or "email" in h or "contact" in h):
        return "STAKEHOLDERS"
        
    # 2. PROJECT STATUS / TIMELINE
    if ("activity" in h or "task" in h) and ("date" in h or "status" in h or "progress" in h):
        return "PROJECT_STATUS"
        
    # 3. ISSUES / CONCERNS
    if "concern" in h and ("status" in h or "comment" in h):
        return "ISSUES_LIST"
        
    # 4. VULNERABILITIES (Technical)
    if "vulnerability" in h or "observation" in h or "severity" in h or "cve" in h:
        return "VULNERABILITIES"
        
    return "GENERIC"

def clean_markdown_noise(text: str) -> str:
    lines = text.split('\n')
    cleaned_lines = []
    footer_patterns = [
        r'^\d+\s*\|\s*Page', r'^Page\s*\d+', r'.*@.*\.\w+$', r'^Confidential$', r'^--- PAGE \d+ ---$'
    ]
    for line in lines:
        is_noise = False
        for pat in footer_patterns:
            if re.search(pat, line.strip(), re.IGNORECASE):
                is_noise = True; break
        if not is_noise: cleaned_lines.append(line)
    return "\n".join(cleaned_lines)

def detect_section_context(line: str, current_context: dict) -> dict:
    line_clean = line.strip()
    if re.match(r'^[A-Z]\.\s', line_clean) or "Key Observations" in line_clean:
        section_name = line_clean.replace("Key Observations", "").replace("-", "").strip()
        current_context['section_name'] = section_name

    line_lower = line.lower()
    if "critical severity" in line_lower: current_context['severity'] = 10.0
    elif "high severity" in line_lower: current_context['severity'] = 8.0
    elif "medium severity" in line_lower: current_context['severity'] = 5.0
    elif "low severity" in line_lower: current_context['severity'] = 2.0
    
    return current_context

# ==============================================================================
# 🧩 ROW PARSERS
# ==============================================================================

def parse_stakeholder_row(parts: List[str], filename: str) -> VulnerabilityRecord:
    rec = VulnerabilityRecord()
    rec.source_file = filename
    rec.asset_id = "PROJECT_TEAM"
    rec.vuln_name = parts[1] if len(parts) > 1 else "Unknown"
    rec.severity = 0.0
    role = parts[2] if len(parts) > 2 else "N/A"
    email = parts[3] if len(parts) > 3 else "N/A"
    contact = parts[4] if len(parts) > 4 else "N/A"
    rec.description = f"Role: {role} | Email: {email} | Contact: {contact}"
    return rec

def parse_status_row(parts: List[str], filename: str) -> VulnerabilityRecord:
    rec = VulnerabilityRecord()
    rec.source_file = filename
    rec.asset_id = "PROJECT_TIMELINE"
    rec.vuln_name = parts[1] if len(parts) > 1 else "Activity"
    rec.severity = 0.0
    status = parts[2] if len(parts) > 2 else "N/A"
    start_date = parts[3] if len(parts) > 3 else "N/A"
    end_date = parts[4] if len(parts) > 4 else "N/A"
    progress = parts[5] if len(parts) > 5 else "N/A"
    rec.description = f"Status: {status} | Start: {start_date} | End: {end_date} | Progress: {progress}"
    return rec

def parse_issue_row(parts: List[str], filename: str) -> VulnerabilityRecord:
    rec = VulnerabilityRecord()
    rec.source_file = filename
    rec.asset_id = "PROJECT_ISSUES"
    rec.vuln_name = parts[1] if len(parts) > 1 else "Concern"
    rec.severity = 5.0
    date = parts[2] if len(parts) > 2 else ""
    status = parts[3] if len(parts) > 3 else ""
    comment = parts[4] if len(parts) > 4 else ""
    rec.description = f"Date: {date} | Status: {status} | Comment: {comment}"
    return rec

def parse_vuln_row(parts: List[str], filename: str, context: dict) -> VulnerabilityRecord:
    rec = VulnerabilityRecord()
    rec.source_file = filename
    if 'severity' in context: rec.severity = context['severity']
    
    text_blobs = []
    for p in parts:
        if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', p) and "version" not in p.lower():
            rec.asset_id = p.strip(); continue
        cves = re.findall(r'CVE-\d{4}-\d+', p)
        if cves: rec.cve_id.extend(cves)
        if "High" in p: rec.severity = 8.0
        elif "Medium" in p: rec.severity = 5.0
        elif "Low" in p: rec.severity = 2.0
        if len(p) > 2: text_blobs.append(p)

    if text_blobs:
        text_blobs.sort(key=len)
        rec.vuln_name = text_blobs[0]
        if len(text_blobs) > 1: rec.description = " | ".join(text_blobs[1:])
    
    if not rec.asset_id:
        rec.asset_id = context.get('section_name', 'General_Observations')

    return rec

# ==============================================================================
# 🚀 MAIN PIPELINE
# ==============================================================================

def process_pdf_layout(pdf_path: str, filename: str) -> List[VulnerabilityRecord]:
    print(f"  - [PDF Engine] 📑 Converting '{filename}' to Smart Markdown...")
    try:
        raw_md = pymupdf4llm.to_markdown(pdf_path)
        md_text = clean_markdown_noise(raw_md)
    except Exception as e:
        print(f"  - [PDF Engine] 🔴 Layout conversion failed: {e}")
        return []
    
    records = []
    lines = md_text.split('\n')
    current_context = {}
    inside_table = False
    current_table_type = "GENERIC"
    
    print("  - [PDF Engine] 🧠 Analyzing document structure...")

    for i, line in enumerate(lines):
        clean_line = line.strip()
        if not clean_line: continue

        if not inside_table and (clean_line.startswith("#") or clean_line[0].isupper()):
            current_context = detect_section_context(clean_line, current_context)
            
        if "|" in clean_line and not inside_table:
            if i + 1 < len(lines) and "---" in lines[i+1]:
                current_table_type = identify_table_type(clean_line)
                inside_table = True
                print(f"  - [PDF Engine] 🏷️ Detected Table Type: {current_table_type}")
                continue 

        if "|" in clean_line and inside_table:
            if "---" in clean_line: continue
            parts = [p.strip() for p in clean_line.split('|') if p.strip()]
            if not parts: continue
            
            if current_table_type == "STAKEHOLDERS":
                records.append(parse_stakeholder_row(parts, filename))
            elif current_table_type == "PROJECT_STATUS":
                records.append(parse_status_row(parts, filename))
            elif current_table_type == "ISSUES_LIST":
                records.append(parse_issue_row(parts, filename))
            else:
                rec = parse_vuln_row(parts, filename, current_context)
                if rec.vuln_name and "Plugin Name" not in rec.vuln_name:
                    records.append(rec)
                    
        if inside_table and "|" not in clean_line:
            inside_table = False
            current_table_type = "GENERIC"
            
    # 5. FALLBACK SUMMARY SCAN
    summary_pattern = r'(?:Total)?\s*(Critical|High|Medium)\s*(?:Severity)?\s*(?:Vulnerabilities|Count)?\s*[:]\s*(\d+)'
    matches = re.findall(summary_pattern, md_text, re.IGNORECASE)
    for severity, count in matches:
        if not any(r.asset_id == "REPORT_SUMMARY" and count in r.description for r in records):
            rec = VulnerabilityRecord()
            rec.source_file = filename
            rec.asset_id = "REPORT_SUMMARY"
            rec.vuln_name = f"Total {severity.title()} Vulnerabilities"
            rec.severity = 10.0 if "crit" in severity.lower() else 5.0
            rec.description = f"Narrative text indicates {count} {severity} severity vulnerabilities."
            records.append(rec)

    # 6. ENRICHMENT (Only load model here, if needed)
    # If no records found, try deep scan
    if not records:
        ner = get_ner_model()
        if ner:
            # (Add deep scan logic here if needed, omitted for brevity/stability)
            pass

    print(f"  - [PDF Engine] ✅ Extracted {len(records)} intelligent records.")
    return records
