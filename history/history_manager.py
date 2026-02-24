import os
import json
from datetime import datetime
from typing import List, Dict

# Define where chat logs are stored
# We use a 'chats' directory in the backend root
BACKEND_ROOT = os.path.dirname(os.path.abspath(__file__))
CHATS_DIR = os.path.join(BACKEND_ROOT, "chats")

class HistoryManager:
    """
    Manages persistent chat history for 'Real LLM' memory.
    Stores conversations as JSON files in backend/chats/{session_id}.json
    """

    @staticmethod
    def _get_file_path(session_id: str) -> str:
        os.makedirs(CHATS_DIR, exist_ok=True)
        # Sanitize session_id to prevent path traversal
        clean_id = "".join(c for c in session_id if c.isalnum() or c in ('-', '_'))
        return os.path.join(CHATS_DIR, f"{clean_id}.json")

    @staticmethod
    def save_interaction(session_id: str, user_query: str, ai_response: str, user_id: str = None):
        """Appends a new turn to the session file."""
        file_path = HistoryManager._get_file_path(session_id)
        
        turn = {
            "timestamp": datetime.now().isoformat(),
            "role": "user",
            "content": user_query
        }
        
        response_turn = {
            "timestamp": datetime.now().isoformat(),
            "role": "assistant",
            "content": ai_response
        }

        data = {"messages": [], "user_id": user_id, "timestamp": datetime.now().isoformat()}
        
        if os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = json.load(f)
                    if isinstance(content, list): # Legacy format
                        data["messages"] = content
                    elif isinstance(content, dict):
                        data = content
                        if user_id and not data.get("user_id"): # Backfill user_id if missing
                             data["user_id"] = user_id
            except json.JSONDecodeError:
                pass # Corrupt file, start fresh

        data["messages"].append(turn)
        data["messages"].append(response_turn)
        data["last_updated"] = datetime.now().isoformat()

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            
        print(f"  - [History] 💾 Saved interaction to {os.path.basename(file_path)}")

    @staticmethod
    def get_recent_context(session_id: str, limit: int = 6) -> List[Dict[str, str]]:
        """
        Loads the last N messages to provide context.
        """
        file_path = HistoryManager._get_file_path(session_id)
        
        if not os.path.exists(file_path):
            return []
            
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = json.load(f)
                
            messages = content if isinstance(content, list) else content.get("messages", [])
                
        except Exception:
            return []

        # Return only the last 'limit' messages (tail)
        context = []
        for turn in messages[-limit:]:
            context.append({
                "role": turn["role"],
                "content": turn["content"]
            })
            
        if context:
            print(f"  - [History] 📖 Loaded {len(context)} previous messages for context.")
            
        return context

    @staticmethod
    def get_user_sessions(user_id: str) -> List[Dict]:
        """Returns all sessions matching the user_id."""
        sessions = []
        os.makedirs(CHATS_DIR, exist_ok=True)
        
        for filename in os.listdir(CHATS_DIR):
            if not filename.endswith(".json"): continue
            
            file_path = os.path.join(CHATS_DIR, filename)
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = json.load(f)
                    
                # Handle Legacy (List) vs New (Dict)
                stored_user_id = content.get("user_id") if isinstance(content, dict) else None
                
                # If we want to be strict:
                if stored_user_id == user_id:
                     session_id = filename.replace(".json", "")
                     msgs = content.get("messages", [])
                     preview = msgs[0]["content"][:50] + "..." if msgs else "Empty Session"
                     timestamp = content.get("timestamp") or (msgs[0]["timestamp"] if msgs else None)
                     
                     sessions.append({
                         "session_id": session_id,
                         "timestamp": timestamp or datetime.now().isoformat(),
                         "preview": preview
                     })
                     
            except Exception:
                continue
                
        # Sort by timestamp desc
        sessions.sort(key=lambda x: x["timestamp"], reverse=True)
        return sessions

    @staticmethod
    def get_full_history(session_id: str) -> List[Dict]:
         file_path = HistoryManager._get_file_path(session_id)
         if not os.path.exists(file_path):
             return []
             
         try:
             with open(file_path, "r", encoding="utf-8") as f:
                 content = json.load(f)
                 return content if isinstance(content, list) else content.get("messages", [])
         except:
             return []
