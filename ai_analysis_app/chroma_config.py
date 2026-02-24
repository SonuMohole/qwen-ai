import os

# Calculate strictly from this file's location
# If this file is in backend/ai_analysis_app/, this puts DB in backend/chroma_db
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHROMA_DB_PATH = os.path.join(BASE_DIR, "chroma_db")

print(f"  - [Config] 📂 ChromaDB Path: {CHROMA_DB_PATH}")
