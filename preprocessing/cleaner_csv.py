import pandas as pd
import re
import os
import difflib
from typing import List, Dict, Any, Optional
from .schema import VulnerabilityRecord

# 🔌 CONNECT THE NEW ENGINES (Graceful Fallback)
try:
    from .cleaner_pdf import process_pdf_layout
except ImportError:
    process_pdf_layout = None

try:
    from .cleaner_docx import process_docx_report
except ImportError:
    process_docx_report = None

# --- CONFIGURATION: SEMANTIC CONCEPTS ---
CONCEPT_MAP = {
    # Identity
    "vuln_name": [
        "vulnerability name", "vuln title", "issue", "threat name", "title", "name", 
        "plugin name", "observation", "finding", "vulnerability", "check name", 
        "vulnerability title"
    ],
    "vuln_id": ["vulnerability id", "plugin id", "qid", "id", "cve id", "sr. no.", "sr no"],
    "category": ["vulnerability category", "category", "family", "class", "plugin family"],
    
    # Asset
    "asset_id": [
        "ip address", "ip", "host ip", "target", "asset", "host", "hostname", 
        "netbios", "host ip address"
    ],
    "hostname": ["hostname", "host name", "dns name", "netbios name", "fqdn"],
    "os": ["operating system", "os", "system os", "platform"],
    "branch": ["branch", "location", "site", "department"],
    
    # Technical
    "port": ["port", "service port", "service"],
    "protocol": ["protocol", "proto", "service protocol"],
    
    # Risk
    "cvss_base_score": ["cvss v3.0 base score", "cvss score", "cvss", "score", "risk score"],
    "risk_level_str": ["risk level", "risk", "severity", "criticality", "risk rating"],
    "cve_id": ["cve id", "cve", "cve identifiers", "cves"],
    
    # Remediation & Context
    "solution": ["recommendation", "solution", "remediation", "fix", "mitigation"],
    "status": [
        "vulnerability patching status remarks", "patching status", "status", "remarks",
        "comments", "team comments", "rajlaxmi bank team comments / remarks",
        "quasar team comments / remarks"
    ],
    "references": ["references", "links", "see also"],
    "description": [
        "description", "summary", "synopsis", "details", "plugin output", 
        "proof", "proof of concept", "evidence", "proof of concept / evidence"
    ]
}

def clean_severity_score(cvss_val: Any, risk_str: Any) -> float:
    try:
        score = float(str(cvss_val).strip())
        if 0 <= score <= 10: return score
    except: pass
    
    s = str(risk_str).lower()
    if "critical" in s: return 10.0
    if "high" in s: return 8.0
    if "medium" in s: return 5.0
    if "low" in s: return 2.0
    return 0.0

def find_header_row(df: pd.DataFrame, scan_limit: int = 20) -> int:
    """Scans the first few rows to find the one with the most matching headers."""
    best_row_idx = 0
    max_matches = 0
    all_concepts = [item for sublist in CONCEPT_MAP.values() for item in sublist]
    
    for i in range(min(len(df), scan_limit)):
        row_values = [str(x).lower().strip() for x in df.iloc[i].values if pd.notna(x)]
        matches = 0
        for val in row_values:
            if val in all_concepts or any(c in val for c in all_concepts):
                matches += 1
        
        if matches > max_matches:
            max_matches = matches
            best_row_idx = i
            
    return best_row_idx

def get_column_map_for_headers(headers: List[str]) -> Dict[str, str]:
    mapping = {}
    for field_key, concepts in CONCEPT_MAP.items():
        best_col = None
        highest_score = 0.0
        
        for header in headers:
            h_clean = str(header).lower().strip()
            # Exact or Substring match
            if any(c == h_clean or c in h_clean for c in concepts):
                score = 1.0 if h_clean in concepts else 0.8
                if score > highest_score:
                    highest_score = score
                    best_col = header
            # Fuzzy match fallback
            elif not best_col:
                matches = difflib.get_close_matches(h_clean, concepts, n=1, cutoff=0.85)
                if matches:
                    best_col = header
        
        if best_col:
            mapping[field_key] = best_col
    return mapping

def parse_dataframe(df: pd.DataFrame, filename: str) -> List[VulnerabilityRecord]:
    """Extracts records from a single DataFrame (Sheet)."""
    # 1. Detect Header Row
    header_idx = find_header_row(df)
    
    # 2. Promote Header Row (CRITICAL FIX: Removed 'if header_idx > 0')
    # We must ALWAYS apply this because pd.read_excel(header=None) returns integers as columns
    new_header = df.iloc[header_idx]
    df = df[header_idx + 1:]
    df.columns = new_header
    
    # 3. Build Column Map
    headers = list(df.columns)
    col_map = get_column_map_for_headers(headers)
    
    # Validation: Only require Title OR IP to accept the sheet
    if "vuln_name" not in col_map and "asset_id" not in col_map:
        return []

    records = []
    for _, row in df.iterrows():
        rec = VulnerabilityRecord()
        rec.source_file = filename
        
        def get(key):
            col = col_map.get(key)
            if col and pd.notna(row[col]):
                return str(row[col]).strip()
            return ""

        rec.vuln_name = get("vuln_name")
        if not rec.vuln_name or rec.vuln_name.lower() in ["nan", "none", "", "vulnerability title"]:
            continue

        rec.vuln_id = get("vuln_id")
        rec.category = get("category")
        rec.asset_id = get("asset_id") or "Unknown_Device"
        rec.hostname = get("hostname")
        rec.os = get("os")
        rec.branch = get("branch") or "Unknown Branch"
        
        rec.port = get("port")
        rec.protocol = get("protocol")
        rec.solution = get("solution")
        rec.status = get("status")
        rec.references = get("references")
        
        desc = get("description")
        rec.description = desc
        
        rec.risk_level_str = get("risk_level_str")
        raw_cvss = get("cvss_base_score")
        rec.severity = clean_severity_score(raw_cvss, rec.risk_level_str)
        try: rec.cvss_base_score = float(raw_cvss)
        except: pass

        cve_text = get("cve_id")
        if cve_text:
            rec.cve_id = re.findall(r'CVE-\d{4}-\d+', cve_text)

        records.append(rec)
        
    return records

def process_tabular_report(file_path: str, filename: str) -> List[VulnerabilityRecord]:
    print(f"  - [NLP Engine] 🧠 Reading {filename}...")
    
    ext = os.path.splitext(filename)[1].lower()
    if ext == '.pdf':
        return process_pdf_layout(file_path, filename) if process_pdf_layout else []
    if ext in ['.docx', '.doc']:
        return process_docx_report(file_path, filename) if process_docx_report else []

    all_records = []
    try:
        if ext in ['.xlsx', '.xls']:
            xls = pd.ExcelFile(file_path)
            print(f"  - [NLP Engine] 📊 Found sheets: {xls.sheet_names}")
            
            for sheet in xls.sheet_names:
                # Read without header initially
                df = pd.read_excel(xls, sheet_name=sheet, header=None)
                sheet_records = parse_dataframe(df, filename)
                if sheet_records:
                    print(f"    - Sheet '{sheet}': Extracted {len(sheet_records)} records")
                    all_records.extend(sheet_records)
                    
        elif ext == '.csv':
            try:
                df = pd.read_csv(file_path, header=None, encoding='utf-8')
            except:
                df = pd.read_csv(file_path, header=None, encoding='latin1')
            all_records = parse_dataframe(df, filename)

        elif ext == '.txt':
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            
            # Simple Text Parsing
            rec = VulnerabilityRecord()
            rec.source_file = filename
            rec.asset_id = "REPORT_NARRATIVE"
            rec.vuln_name = "Full Report Text"
            rec.severity = 0.0
            rec.description = content
            all_records = [rec]

    except Exception as e:
        print(f"  - [NLP Engine] 🔴 Read Error: {e}")
        return []

    print(f"  - [NLP Engine] ✅ Successfully understood {len(all_records)} records.")
    return all_records
