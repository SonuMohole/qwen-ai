import os
from typing import List, Tuple
from .schema import VulnerabilityRecord
from .cleaner_csv import process_tabular_report
from .cleaner_docx import process_docx_report
from .cleaner_pdf import process_pdf_layout
from .smart_chunker import smart_chunk_records

def run_preprocessing_pipeline(file_path: str) -> List[Tuple[str, dict]]:
    """
    Main Entry Point: Detects file type, runs extraction, and applies semantic chunking.
    Returns a list of (Chunk Text, Metadata) tuples ready for RAG ingestion.
    """
    filename = os.path.basename(file_path)
    ext = filename.split('.')[-1].lower()
    
    print(f"\n--- 🏭 Preprocessing Pipeline: {filename} ---")
    
    # 1. Extraction Phase
    records: List[VulnerabilityRecord] = []
    
    if ext in ['csv', 'xlsx', 'xls']:
        records = process_tabular_report(file_path, filename)
    
    elif ext in ['docx', 'doc']:
        # Universal DOCX Extractor (Tables + Narrative)
        records = process_docx_report(file_path, filename)
        
    elif ext == 'pdf':
        # Intelligent Layout PDF Extractor
        records = process_pdf_layout(file_path, filename)
        
    else:
        print(f"❌ Unsupported file type: {ext}")
        return []

    if not records:
        print("⚠️  No records extracted. Aborting chunking.")
        return []

    # 2. Chunking Phase (Smart/Semantic)
    print(f"  - [Pipeline] Passing {len(records)} records to Smart Chunker...")
    chunks = smart_chunk_records(records)
    
    print(f"✅ Pipeline Complete. Optimized {len(chunks)} chunks.")
    return chunks