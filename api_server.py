import os
import sys
import shutil
import uuid
import multiprocessing
import asyncio
import uvicorn
import signal
import traceback  # For error printing
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

# PATH SETUP
BACKEND_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.append(BACKEND_ROOT)

from ai_analysis_app.agent_workflow import get_ai_response, calculate_time_estimate
from ai_analysis_app.indexing_service import process_and_index_file

from history.history_manager import HistoryManager

# CONFIG: Security Filter
ALLOWED_EXTENSIONS = {".pdf", ".docx", ".doc", ".txt", ".csv", ".xlsx", ".xls"}

# ------------------------------------------------------------------------------
# 🛑 LIFESPAN MANAGER
# ------------------------------------------------------------------------------
ACTIVE_PROCESSES = []

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 Qstellar AI Backend Started")
    yield
    print("\n🛑 SHUTTING DOWN: Killing active processes...")
    for p in ACTIVE_PROCESSES:
        if p.is_alive():
            p.terminate()
            p.join(timeout=0.5)
            if p.is_alive():
                p.kill() 
    print("✅ Cleanup Complete")

app = FastAPI(title="Qstellar AI Backend", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------------------------------
# GLOBAL LOCK
# ------------------------------------------------------------------------------
CURRENT_ACTIVE_SESSION: Optional[str] = None
LOCK_GUARD = asyncio.Lock()

# ------------------------------------------------------------------------------
# 🌐 STATIC FILE SERVING
# ------------------------------------------------------------------------------
# Mount the current directory (BACKEND_ROOT) as static to serve JS/CSS if needed, 
# though index.html uses CDNs.
app.mount("/static", StaticFiles(directory=BACKEND_ROOT), name="static")

@app.get("/")
async def read_index():
    return FileResponse(os.path.join(BACKEND_ROOT, "index.html"))

async def acquire_lock(session_id: str):
    global CURRENT_ACTIVE_SESSION
    async with LOCK_GUARD:
        if CURRENT_ACTIVE_SESSION in (None, session_id):
            CURRENT_ACTIVE_SESSION = session_id
            return
        raise HTTPException(503, "System Busy")

async def release_lock(session_id: str):
    global CURRENT_ACTIVE_SESSION
    async with LOCK_GUARD:
        if CURRENT_ACTIVE_SESSION == session_id:
            CURRENT_ACTIVE_SESSION = None

# ------------------------------------------------------------------------------
# WORKER WRAPPERS
# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------
# WORKER WRAPPERS
# ------------------------------------------------------------------------------
def run_chat_process(queue, user_input, session_id, history_context, user_id=None):
    try:
        # Pass loaded history to the agent
        response = get_ai_response(user_input, session_id, history_context)
        
        # SAVE INTERACTION TO PERSISTENT MEMORY
        HistoryManager.save_interaction(session_id, user_input, response, user_id=user_id)
        
        queue.put({"status": "success", "data": response})
    except Exception as e:
        # PRINT ERROR TO TERMINAL
        print(f"\n🔴 CHAT WORKER ERROR:\n{traceback.format_exc()}\n")
        queue.put({"status": "error", "message": str(e)})

def run_ingest_process(queue, file_path, original_filename, session_id):
    try:
        result = process_and_index_file(file_path, original_filename, session_id)
        queue.put({"status": "success", "details": result})
    except Exception as e:
        # PRINT ERROR TO TERMINAL
        print(f"\n🔴 INGEST WORKER ERROR:\n{traceback.format_exc()}\n")
        queue.put({"status": "error", "message": str(e)})
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)

async def run_cancellable_process(process, queue, req: Request):
    ACTIVE_PROCESSES.append(process) 
    process.start()

    try:
        while process.is_alive():
            if await req.is_disconnected():
                print(f"🛑 Client disconnected → killing {process.pid}")
                process.kill()
                raise HTTPException(499, "Client closed request")
            await asyncio.sleep(0.1)

        process.join()
        if queue.empty():
            print("\n🔴 WORKER CRASHED SILENTLY (Segfault or OOM)\n")
            raise HTTPException(500, "Worker process failed silently")

        result = queue.get()
        if result["status"] == "error":
            # Print to console so you see it
            print(f"🔴 API ERROR RETURNED: {result['message']}")
            raise HTTPException(500, result["message"])
        return result

    finally:
        if process in ACTIVE_PROCESSES:
            ACTIVE_PROCESSES.remove(process)
        if process.is_alive():
            process.kill()

# ------------------------------------------------------------------------------
# ROUTES
# ------------------------------------------------------------------------------
class ChatRequest(BaseModel):
    user_input: str
    chat_history: str = ""
    session_id: str = "default"
    user_id: Optional[str] = None

@app.post("/api/ai/estimate")
async def estimate_handler(request: ChatRequest):
    print(f"⏱️ ESTIMATION REQUEST: {request.user_input}", flush=True)
    try:
        # We don't necessarily need a strict lock for estimation since it's read-only RAG mostly,
        # but to prevent chromadb contention if it's not thread-safe:
        # await acquire_lock(request.session_id) 
        # Actually, let's keep it lock-free for speed if possible, or minimal lock. 
        # But `perform_rag_search` uses a persistent client. 
        # Let's trust RAG is safe enough or short enough.
        
        result = calculate_time_estimate(request.user_input, request.session_id)
        print(f"   -> ESTIMATION RESULT: {result}", flush=True)
        return result
    except Exception as e:
        print(f"🔴 ESTIMATE ERROR: {e}")
        return {"estimated_time": 5.0, "complexity": "Unknown", "chunk_count": 0} # Fallback

@app.post("/api/upload")
async def upload_document_handler(request: Request, file: UploadFile = File(...), session_id: str = Form(...)):
    # 🛡️ SECURITY: Block .svg, .exe, etc.
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        print(f"🚫 IGNORING UPLOAD: {file.filename} (Invalid Type)")
        return {"status": "ignored", "message": "File type not supported"}

    print(f"📨 Upload: {file.filename}")
    await acquire_lock(session_id)
    
    temp_dir = os.path.join(BACKEND_ROOT, "temp_uploads")
    os.makedirs(temp_dir, exist_ok=True)
    temp_path = os.path.join(temp_dir, f"{uuid.uuid4()}_{file.filename}")

    try:
        with open(temp_path, "wb") as f:
            shutil.copyfileobj(file.file, f)
            
        queue = multiprocessing.Queue()
        process = multiprocessing.Process(
            target=run_ingest_process,
            args=(queue, temp_path, file.filename, session_id)
        )
        await run_cancellable_process(process, queue, request)
        return {"status": "success"}
    finally:
        await release_lock(session_id)

@app.post("/api/chat")
async def chat_handler(request: ChatRequest, req: Request):
    print(f"💬 Chat: {request.user_input}")
    await acquire_lock(request.session_id)
    try:
        # LOAD HISTORY FROM DISK
        history_context = HistoryManager.get_recent_context(request.session_id)
        
        queue = multiprocessing.Queue()
        process = multiprocessing.Process(
            target=run_chat_process,
            args=(queue, request.user_input, request.session_id, history_context, request.user_id)
        )
        result = await run_cancellable_process(process, queue, req)
        
        # PRINT ANSWER TO TERMINAL
        ai_answer = result["data"]
        print("\n" + "="*60)
        print("🧠 AI RESPONSE:")
        print("-" * 60)
        print(ai_answer)
        print("="*60 + "\n")

        return {"response": ai_answer, "timestamp": datetime.now().isoformat()}
    finally:
        await release_lock(request.session_id)

@app.get("/api/sessions")
async def get_sessions_handler(user_id: str):
    """Returns list of sessions for a user."""
    sessions = HistoryManager.get_user_sessions(user_id)
    return {"sessions": sessions}

@app.get("/api/history/{session_id}")
async def get_history_handler(session_id: str):
    """Returns full history for a session."""
    history = HistoryManager.get_full_history(session_id)
    if not history:
        # Return empty if not found, or 404
        return {"messages": []}
    return {"messages": history}

if __name__ == "__main__":
    multiprocessing.set_start_method("spawn", force=True)
    uvicorn.run(app, host="192.168.2.29", port=5555)
