import os
import chromadb
import re
import random
from .model_manager import ModelManager

try:
    from .chroma_config import CHROMA_DB_PATH
except ImportError:
    from chroma_config import CHROMA_DB_PATH

from .indexing_service import get_embed_model
from .prompts import CHAT_SYSTEM_PROMPT, SYNTHESIS_SYSTEM_PROMPT, HYDE_SYSTEM_PROMPT

EMBED_MODEL = get_embed_model()

def generate_hypothetical_document(query: str) -> str:
    messages = [{"role": "system", "content": HYDE_SYSTEM_PROMPT}, {"role": "user", "content": query}]
    return ModelManager.chat(messages).strip('"').strip("'")

def is_pure_conversation(text: str) -> bool:
    t = text.lower().strip()
    if t in ["hi", "hello", "thanks", "ok", "bye"]: return True
    return any(re.search(pat, t) for pat in [r"^who are you", r"^what (can|do) you do"])

def get_report_registry(collection) -> list:
    try:
        results = collection.get(include=["metadatas"])
        metadatas = results.get("metadatas", [])
        unique_reports = {}
        for m in metadatas:
            if "report_id" in m:
                unique_reports[m["report_id"]] = {
                    "filename": m.get("source_filename", "Unknown"),
                    "timestamp": m.get("upload_timestamp", "0")
                }
        return sorted(unique_reports.items(), key=lambda x: x[1]['timestamp'], reverse=True)
    except Exception: return []

def build_search_filters(query: str) -> dict:
    q = query.lower()
    filters = {}
    
    # 1. RISK LEVEL MAPPING
    risk_levels = []
    if "critical" in q: risk_levels.append("CRITICAL")
    if "high" in q: risk_levels.append("HIGH")
    if "medium" in q: risk_levels.append("MEDIUM")
    if "low" in q: risk_levels.append("LOW")
    if "info" in q: risk_levels.append("INFO")

    if risk_levels:
        if len(risk_levels) == 1:
            filters["risk_label"] = risk_levels[0]
        else:
            filters["risk_label"] = {"$in": risk_levels}

    # 2. CHUNK TYPE MAPPING (Optional but good for specificity)
    if "summary" in q or "overview" in q:
        filters["chunk_type"] = {"$in": ["summary", "executive_risk"]}

    print(f"   -> [RAG] Filters: {filters}", flush=True)
    return filters

# ==============================================================================
# 🔍 BALANCED RETRIEVAL (STOPS HALLUCINATION)
# ==============================================================================
def perform_rag_search(session_id: str, query: str) -> str:
    client = chromadb.PersistentClient(path=CHROMA_DB_PATH)
    try:
        collection = client.get_collection(f"{session_id}_phase1")
    except Exception: return ""

    registry = get_report_registry(collection)
    if not registry: return ""
    
    is_comparison = any(x in query.lower() for x in ["compare", "difference", "previous", "history", "trend", "both", "reports", "changes", "updates"])
    raw_filters = build_search_filters(query)
    query_embedding = EMBED_MODEL.get_text_embedding(f"search_query: {generate_hypothetical_document(query)}")

    final_docs = []
    final_metas = []

    
    # DYNAMIC RETRIEVAL LIMIT (ROBUSTNESS FIX)
    # If the user asks for a "list", "summary", or "all" items, we need a wider net to catch split lists.
    # Otherwise, we keep it focused to avoid context pollution.
    broad_keywords = ["list", "all", "summary", "overview", "total", "report", "vulnerabilities"]
    if any(k in query.lower() for k in broad_keywords):
        target_n_results = 20 # INCREASED to capture more items
        print("  - [RAG] 🌊 Broad Query Detected: Increasing retrieval to 20 chunks", flush=True)
    else:
        target_n_results = 7  # Focused net for specific questions
        print("  - [RAG] 🎯 Specific Query Detected: Using 7 chunks", flush=True)

    def query_chroma(filter_dict, n_results):
        # Helper to construct proper Chroma 'where' clause
        if not filter_dict:
            return {}, {}
            
        # If multiple conditions, use $and. If single, use directly.
        # Note: Chroma's $in is a value operator, not a top-level operator like $and
        if len(filter_dict) > 1:
            where_filter = {"$and": [{k: v} for k, v in filter_dict.items()]}
        else:
            where_filter = filter_dict
            
        res = collection.query(
            query_embeddings=[query_embedding],
            n_results=n_results,
            where=where_filter,
            include=["documents", "metadatas"]
        )
        return res.get("documents", [[]])[0], res.get("metadatas", [[]])[0]

    if is_comparison and len(registry) > 1:
        print("  - [RAG] 🔄 Balanced Retrieval: Fetching separate chunks for LATEST and PREVIOUS reports")
        # Ensure we get data from BOTH of the most recent reports
        for report_id, report_info in registry[:2]:
            report_filter = raw_filters.copy()
            report_filter["report_id"] = report_id
            
            docs, metas = query_chroma(report_filter, 10)
            final_docs.extend(docs)
            final_metas.extend(metas)
    else:
        print("  - [RAG] 🔎 Standard Retrieval: Focusing on LATEST report only", flush=True)
        # Standard retrieval for single report
        raw_filters["report_id"] = registry[0][0]
        
        docs, metas = query_chroma(raw_filters, target_n_results)
        final_docs = docs
        final_metas = metas

    if not final_docs: 
        print("  - [RAG] ⚠️ No chunks found with applied filters.", flush=True)
        return ""

    context = "### MULTI-REPORT DATA SOURCE (STRICT ISOLATION):\n\n"
    for i, (doc, meta) in enumerate(zip(final_docs, final_metas), 1):
        report_type = "LATEST_REPORT" if meta.get('report_id') == registry[0][0] else "PREVIOUS_REPORT"
        
        # DEBUG LOGGING
        print(f"    -> [Chunk {i}] ID: {meta.get('vuln_id', 'N/A')} | Risk: {meta.get('risk_label')} | Type: {meta.get('chunk_type')}", flush=True)
        
        context += (
            f"[[ DATA_BLOCK_{i} | STATUS: {report_type} | ID: {meta.get('report_id')} ]]\n"
            f"SOURCE_FILE: {meta.get('source_filename')}\n"
            f"UPLOAD_DATE: {meta.get('upload_timestamp')}\n"
            f"RISK_LABEL: {meta.get('risk_label')}\n"
            f"CONTENT: {doc}\n"
            f"[[ END_BLOCK_{i} ]]\n\n"
        )
    return context

def analyze_question_complexity(question: str) -> str:
    """Analyzes the complexity of the user's question."""
    question = question.lower().strip()
    words = question.split()
    
    # High complexity keywords
    high_keywords = [
        "summarize", "summary", "explain", "analyze", "compare", 
        "details", "report", "difference", "comprehensive",
        "table", "breakdown", "analysis", "recommend", "how to"
    ]
    
    # Low complexity keywords
    low_keywords = [
        "what is", "who is", "when", "where", "define", "name", "list"
    ]
    
    if any(k in question for k in high_keywords) or len(words) > 30:
        return "High"
    
    if any(k in question for k in low_keywords) and len(words) < 10:
        return "Low"
        
    return "Medium"

def calculate_time_estimate(question: str, session_id: str) -> dict:
    """
    Calculates estimated time based on retrieved chunks, context length, and question complexity.
    """
    # 1. Get Context (Hit the DB)
    print(f"   -> [Estimator] Analyzing complexity for: {question}", flush=True)
    context = perform_rag_search(session_id, question)
    
    # DEBUG: Print context to terminal for analysis
    print(f"\n[DEBUG] Retrieved Context:\n{context}\n[DEBUG] End Context\n", flush=True)
    
    # 2. Count Chunks & Length
    chunk_count = context.count("[[ DATA_BLOCK_")
    context_length = len(context)
    print(f"   -> [Estimator] Found {chunk_count} chunks, {context_length} chars", flush=True)
    
    # 3. Analyze Complexity
    complexity = analyze_question_complexity(question)
    
    # 4. Calculate Time Components
    base_overhead = 1.0
    retrieval_latency = 0.5 * chunk_count
    reading_time = context_length / 5000.0  # Simulating LLM reading speed
    
    # Generation Time (Randomized for realism and variety)
    if complexity == "High":
        generation_time = random.uniform(12.0, 25.0)
    elif complexity == "Medium":
        generation_time = random.uniform(5.0, 10.0)
    else: # Low
        generation_time = random.uniform(2.0, 4.0)
    
    total_seconds = base_overhead + retrieval_latency + reading_time + generation_time
    
    # Range Clamping (Min 2s, Max 120s)
    estimated_time = round(min(max(total_seconds, 2.0), 120.0), 1)
    
    result = {
        "estimated_time": estimated_time,
        "complexity": complexity,
        "chunk_count": chunk_count
    }
    print(f"   -> [Estimator] Calculation: {base_overhead} + {retrieval_latency} + {reading_time:.2f} + {generation_time:.2f} = {total_seconds:.2f}s", flush=True)
    return result

def get_ai_response(user_input: str, session_id: str, chat_history: list = None) -> str:
    if chat_history is None: chat_history = []
    
    # FRESH CONTEXT STRATEGY: 
    # Only keep the last 1 exchange to prevent history from pushing out the RAG context.
    # The user explicitly requested "fresh" context for each question.
    limited_history = chat_history[-2:] if len(chat_history) > 2 else chat_history
    
    messages = [{"role": "system", "content": CHAT_SYSTEM_PROMPT}] + limited_history
    
    if is_pure_conversation(user_input):
        messages.append({"role": "user", "content": user_input})
        return ModelManager.chat(messages)

    context = perform_rag_search(session_id, user_input)
    if not context.strip():
        messages.append({"role": "user", "content": user_input})
        return ModelManager.chat(messages)

    rag_messages = [{"role": "system", "content": SYNTHESIS_SYSTEM_PROMPT}] + limited_history
    rag_messages.append({"role": "user", "content": f"USER QUESTION:\n{user_input}\n\nRETRIEVED CONTEXT:\n{context}"})
    return ModelManager.chat(rag_messages)