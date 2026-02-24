# backend/ai_analysis_app/tools_sql.py

import os
import re
import json
import psycopg2
from psycopg2.extras import RealDictCursor
from typing import List, Dict, Any, Optional

# --- INTERNAL IMPORTS ---
from .model_manager import ModelManager
from .db_schema_context import get_sql_context_prompt

# --- DATABASE CONFIGURATION ---
PG_DB_NAME = os.getenv("PG_DB_NAME")
PG_USER = os.getenv("PG_USER")
PG_PASSWORD = os.getenv("PG_PASSWORD")
PG_HOST = os.getenv("PG_HOST")

def get_db_connection():
    """Establishes a connection to the PostgreSQL database."""
    try:
        conn = psycopg2.connect(
            dbname=PG_DB_NAME,
            user=PG_USER,
            password=PG_PASSWORD,
            host=PG_HOST
        )
        return conn
    except Exception as e:
        print(f"  - [SQL Tool] 🔴 DB Connection Failed: {e}")
        return None

def sanitize_sql_output(llm_response: str) -> str:
    """
    Cleans the LLM output to extract ONLY the SQL query.
    Removes markdown backticks, explanations, and whitespace.
    """
    # 1. Remove Markdown code blocks (```sql ... ```)
    match = re.search(r"```sql\s*(.*?)\s*```", llm_response, re.DOTALL | re.IGNORECASE)
    if match:
        sql = match.group(1)
    else:
        # Fallback: simple strip if no markdown found
        sql = llm_response.replace("```", "").strip()

    # 2. Clean extra whitespace
    sql = " ".join(sql.split())

    # 🚀 NEW GUARDRAIL: If it doesn't look like a query, REJECT IT.
    # This catches instances where the model generates conversation instead of SQL.
    valid_starts = ["SELECT", "WITH", "VALUES"]
    if not any(sql.upper().startswith(kw) for kw in valid_starts):
        print(f"  - [SQL Tool] 🛑 Output is not SQL. Rejecting: {sql[:50]}...")
        return ""

    # 3. Safety: Ensure it doesn't contain dangerous commands
    forbidden = ["DROP ", "DELETE ", "TRUNCATE ", "ALTER ", "INSERT ", "UPDATE ", "GRANT "]
    if any(cmd in sql.upper() for cmd in forbidden):
        print(f"  - [SQL Tool] 🛑 Blocked dangerous query: {sql}")
        return ""
    
    return sql

def execute_raw_sql(query: str) -> List[Dict[str, Any]]:
    """
    Executes a read-only SQL query and returns JSON-ready dictionaries.
    """
    if not query:
        return []

    conn = get_db_connection()
    if not conn:
        return [{"error": "Database unavailable"}]

    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            print(f"  - [SQL Tool] ⚡ Executing: {query}")
            cur.execute(query)
            results = cur.fetchall()
            
            # Convert RealDictRow to standard dict for JSON serialization
            return [dict(row) for row in results]
            
    except Exception as e:
        print(f"  - [SQL Tool] 🔴 Query Execution Error: {e}")
        return [{"error": f"SQL Execution Failed: {str(e)}"}]
    finally:
        if conn:
            conn.close()

def generate_and_execute_sql(user_query: str, chat_history_str: str) -> Dict[str, Any]:
    """
    The Main Coordinator for Phase 1 & 2:
    1. Loads SQL Expert (JIT).
    2. Generates SQL.
    3. Unloads Model.
    4. Executes SQL in Python.
    5. Returns Data.
    """
    
    # --- PHASE 1: GENERATION (The Architect) ---
    system_prompt = get_sql_context_prompt()
    
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"CHAT HISTORY:\n{chat_history_str}\n\nCURRENT QUESTION: {user_query}"}
    ]

    print(f"  - [SQL Tool] 🧠 invoking SQL Expert...")
    # ModelManager.chat expects a list of messages. We don't support custom 'model' arg in the simple chat method anymore,
    # but the instructions say 'sql_expert' which implies a persona. We pass the messages directly.
    # If the underlying model needs to be different, ModelManager would need an update, but for now we use the main model.
    raw_llm_response = ModelManager.chat(messages)
    
    if not raw_llm_response:
        return {"sql": None, "data": [], "error": "Model failed to generate SQL."}

    # --- PHASE 2: EXECUTION (The Builder) ---
    clean_sql = sanitize_sql_output(raw_llm_response)
    
    if not clean_sql:
        return {"sql": raw_llm_response, "data": [], "error": "Generated SQL was invalid or unsafe."}

    data_results = execute_raw_sql(clean_sql)
    
    return {
        "sql": clean_sql,
        "data": data_results,
        "row_count": len(data_results)
    }
