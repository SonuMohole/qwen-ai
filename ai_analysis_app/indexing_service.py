import os
import chromadb
import gc
import time
import hashlib
from typing import List, Tuple

from llama_index.embeddings.ollama import OllamaEmbedding
from llama_index.core.schema import Document

try:
    from .chroma_config import CHROMA_DB_PATH
except ImportError:
    from chroma_config import CHROMA_DB_PATH

from preprocessing.cleaner_csv import process_tabular_report
from preprocessing.smart_chunker import smart_chunk_records
from preprocessing.schema import VulnerabilityRecord

# ==============================================================================
# 🔐 SINGLETON EMBEDDING MODEL
# ==============================================================================
_EMBED_MODEL = None

# Maximum characters per chunk for embedding (conservative limit to avoid context overflow)
MAX_EMBEDDING_CHARS = 1500

def get_embed_model():
    global _EMBED_MODEL
    if _EMBED_MODEL is None:
        print("  - [Indexing] 🟢 Loading Ollama Embeddings (ONCE)")
        _EMBED_MODEL = OllamaEmbedding(
            model_name="nomic-embed-text",
            base_url="http://localhost:11434",
            timeout=120
        )
    return _EMBED_MODEL

def split_oversized_chunk(text: str, metadata: dict, max_chars: int = MAX_EMBEDDING_CHARS) -> List[Tuple[str, dict]]:
    """
    Splits a chunk that's too large for embedding into smaller sub-chunks.
    Preserves metadata for each sub-chunk.
    """
    if len(text) <= max_chars:
        return [(text, metadata)]
    
    sub_chunks = []
    # Split by paragraphs first
    paragraphs = text.split('\n\n')
    
    current_chunk = []
    current_len = 0
    part_num = 1
    
    for para in paragraphs:
        para_len = len(para)
        
        if current_len + para_len > max_chars:
            if current_chunk:
                # Save current chunk
                chunk_text = '\n\n'.join(current_chunk)
                chunk_meta = metadata.copy()
                chunk_meta['sub_part'] = part_num
                sub_chunks.append((chunk_text, chunk_meta))
                
                current_chunk = []
                current_len = 0
                part_num += 1
            
            # If single paragraph is too large, split it by sentences
            if para_len > max_chars:
                sentences = para.split('. ')
                for sentence in sentences:
                    if current_len + len(sentence) > max_chars and current_chunk:
                        chunk_text = '\n\n'.join(current_chunk)
                        chunk_meta = metadata.copy()
                        chunk_meta['sub_part'] = part_num
                        sub_chunks.append((chunk_text, chunk_meta))
                        
                        current_chunk = []
                        current_len = 0
                        part_num += 1
                    
                    current_chunk.append(sentence)
                    current_len += len(sentence)
            else:
                current_chunk.append(para)
                current_len += para_len
        else:
            current_chunk.append(para)
            current_len += para_len
    
    # Add remaining chunk
    if current_chunk:
        chunk_text = '\n\n'.join(current_chunk)
        chunk_meta = metadata.copy()
        chunk_meta['sub_part'] = part_num
        sub_chunks.append((chunk_text, chunk_meta))
    
    return sub_chunks

# ==============================================================================
# 📥 INGEST + INDEX
# ==============================================================================
def process_and_index_file(file_path: str, original_filename: str, session_id: str) -> dict:
    print(f"  - [Indexing] 📄 Processing upload: {original_filename}")

    # 1️⃣ Parse
    records: List[VulnerabilityRecord] = process_tabular_report(file_path, original_filename)
    if not records: return {"error": "No valid vulnerability records parsed"}

    # 2️⃣ Chunk
    chunks: List[Tuple[str, dict]] = smart_chunk_records(records)

    # 3️⃣ Connect
    client = chromadb.PersistentClient(path=CHROMA_DB_PATH)
    collection_name = f"{session_id}_phase1"
    collection = client.get_or_create_collection(collection_name)

    # NEW: Descriptive ID for better AI recognition (Hallucination Guard)
    short_hash = hashlib.md5(f"{original_filename}".encode()).hexdigest()[:5]
    report_id = f"REP_{short_hash}_{int(time.time())}" 
    upload_timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    # 4️⃣ Prepare and Inject Metadata + Validate Chunk Sizes
    documents = []
    oversized_count = 0
    
    for text, metadata in chunks:
        metadata["report_id"] = report_id
        metadata["source_filename"] = original_filename
        metadata["upload_timestamp"] = upload_timestamp
        
        # Check if chunk is too large and split if necessary
        if len(text) > MAX_EMBEDDING_CHARS:
            oversized_count += 1
            sub_chunks = split_oversized_chunk(text, metadata)
            for sub_text, sub_meta in sub_chunks:
                documents.append(Document(text=sub_text, metadata=sub_meta))
        else:
            documents.append(Document(text=text, metadata=metadata))
    
    if oversized_count > 0:
        print(f"  - [Indexing] ⚠️  Split {oversized_count} oversized chunks into smaller pieces")

    # 5️⃣ Embed in Batches (safer for large reports)
    embed_model = get_embed_model()
    raw_texts = [doc.text for doc in documents]
    prefixed_texts = [f"search_document: {t}" for t in raw_texts]
    
    # Process in smaller batches to avoid overwhelming the embedding model
    BATCH_SIZE = 10
    all_embeddings = []
    
    for i in range(0, len(prefixed_texts), BATCH_SIZE):
        batch = prefixed_texts[i:i+BATCH_SIZE]
        try:
            batch_embeddings = embed_model.get_text_embedding_batch(batch)
            all_embeddings.extend(batch_embeddings)
            print(f"  - [Indexing] 📦 Embedded batch {i//BATCH_SIZE + 1}/{(len(prefixed_texts)-1)//BATCH_SIZE + 1}")
        except Exception as e:
            print(f"  - [Indexing] ❌ Error embedding batch {i//BATCH_SIZE + 1}: {e}")
            # Try individual chunks in this batch
            for j, single_text in enumerate(batch):
                try:
                    single_embedding = embed_model.get_text_embedding(single_text)
                    all_embeddings.append(single_embedding)
                except Exception as e2:
                    print(f"  - [Indexing] ❌ Skipping chunk {i+j} (too large): {len(single_text)} chars")
                    # Use a zero embedding as fallback
                    all_embeddings.append([0.0] * 768)  # nomic-embed-text dimension

    collection.add(
        documents=raw_texts, 
        metadatas=[doc.metadata for doc in documents],
        embeddings=all_embeddings,
        ids=[f"{report_id}_{i}" for i in range(len(raw_texts))]
    )

    print(f"  - [Indexing] ✅ Added {len(raw_texts)} items to DB for report {report_id}")

    del collection
    del client
    gc.collect()
    return {"status": "success", "report_id": report_id}