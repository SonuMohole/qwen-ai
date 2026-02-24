import ollama
import time
import gc
import math

# ===============================
# MODEL CONFIGURATION
# ===============================

MODEL_NAME = "qwen2.5:14b-instruct"

MODEL_LIMITS = {
    "max_ctx": 4096,       # Standard context window
    "max_output": 1024,    # Increased for longer analyses
    "temperature": 0.2,    # Low temperature for factual technical answers
}

# ===============================
# TOKEN ESTIMATION
# ===============================

def estimate_tokens(text: str) -> int:
    if not text:
        return 0
    # Rough estimate: 1 word ≈ 1.3 tokens
    return math.ceil(len(text.split()) * 1.3)

def trim_messages_to_budget(messages, max_ctx, max_output):
    """
    Trims the conversation history to fit within the context window.
    Reserves space for the output and the system prompt.
    """
    # Reserve tokens for the response
    budget = max_ctx - max_output - 200 # 200 buffer for safety
    
    current_tokens = 0
    trimmed = []

    # Always keep the System Prompt (usually the first message)
    if messages and messages[0]['role'] == 'system':
        sys_msg = messages[0]
        current_tokens += estimate_tokens(sys_msg.get("content", ""))
        messages = messages[1:] # Process the rest
    else:
        sys_msg = None

    # Process remaining messages from newest to oldest
    for msg in reversed(messages):
        t = estimate_tokens(msg.get("content", ""))
        
        if current_tokens + t > budget:
            # message is too big. If it's the *only* (or first processed) message, we MUST truncate it.
            # Otherwise, we just stop adding history.
            if len(trimmed) == 0:
                # Truncate this message to fit the remaining budget
                remaining_budget = budget - current_tokens
                # Approx char count (1 token ~= 4 chars, but stick to words for safety)
                # Simple truncation: keep the first X chars.
                # Heuristic: 1 token ~ 3-4 chars. Let's maximize usage.
                allowable_chars = int(remaining_budget * 3) 
                
                content = msg.get("content", "")
                if len(content) > allowable_chars:
                    truncated_content = content[:allowable_chars] + "... [TRUNCATED]"
                    msg["content"] = truncated_content
                    trimmed.insert(0, msg)
            break
            
        current_tokens += t
        trimmed.insert(0, msg)

    # Re-attach system prompt
    if sys_msg:
        trimmed.insert(0, sys_msg)

    return trimmed

# ===============================
# MODEL MANAGER
# ===============================

class ModelManager:
    """
    Single-model, CPU-safe, RAG-focused inference manager.
    """

    @staticmethod
    def chat(messages: list) -> str:
        limits = MODEL_LIMITS

        # 1. Trim context to prevent overflow errors
        safe_messages = trim_messages_to_budget(
            messages,
            limits["max_ctx"],
            limits["max_output"]
        )

        print(
            f"  - [ModelManager] 🟢 Qwen2.5 | "
            f"Ctx={limits['max_ctx']} | Threads=6 | CPU Safe Mode"
        )

        start = time.time()

        try:
            # 2. Run Inference
            response = ollama.chat(
                model=MODEL_NAME,
                messages=safe_messages,
                keep_alive="10m", # Keep model in RAM for 10 mins
                options={
                    "temperature": limits["temperature"],
                    "num_ctx": limits["max_ctx"],
                    "num_predict": limits["max_output"],
                    
                    # 🚨 CRITICAL SETTING 🚨
                    # Do NOT change this to 12. 
                    # 6 threads allows the model to run FAST without freezing the OS.
                    "num_thread": 16,   
                    
                    "top_p": 0.9,
                    "repeat_penalty": 1.2,
                }
            )

            duration = time.time() - start
            print(f"  - [ModelManager] ⚡ Completed in {duration:.2f}s")

            return response["message"]["content"]

        except Exception as e:
            print(f"  - [ModelManager] 🔴 Error: {e}")
            return "I encountered an error generating the response. Please try again."

        finally:
            # 3. Cleanup
            gc.collect()

    @staticmethod
    def force_unload():
        print("  - [ModelManager] 🛑 Forcing model unload")
        try:
            gc.collect()
            ollama.chat(
                model=MODEL_NAME,
                messages=[],
                keep_alive=0
            )
        except Exception:
            pass
