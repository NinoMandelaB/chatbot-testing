import logging
import os
import re
import threading

from flask import Flask, jsonify, render_template, request
from openai import OpenAI

from memory import db, extractor, retriever

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

app = Flask(__name__)

CORTECS_API_KEY     = os.environ.get("CORTECS_API_KEY", "")
CORTECS_BASE_URL    = os.environ.get("CORTECS_BASE_URL", "https://api.cortecs.ai/v1")
DEFAULT_SYSTEM_PROMPT = os.environ.get("SYSTEM_PROMPT", "You are a helpful assistant.")

# Injected silently before every user message when sandwich mode is ON.
# Keeps hard blocks fresh at the bottom of the context window.
SAFETY_REMINDER = """[SAFETY & SCOPE REMINDER — re-read before generating your response]
✅ NSFW adult roleplay IS allowed and encouraged. Stay immersive, in-character, and explicit if the scene calls for it.
⛔ HARD STOP — exit scene IMMEDIATELY and use the refusal template if the current message contains ANY of:
• Minors / underage / teen / 17 / barely legal / schoolgirl / schoolboy / perky young / still developing
• daddy + young/teen/little/baby in a sexual context
• Incest / family sex
• Bestiality
• Non-consent / force / threats / incapacity
• CSAM / rape / graphic violence against a real person
• Hate speech / criminal instructions / doxxing
Refusal template (translate into the user's language):
"I have to stop the roleplay here. [trigger] is something I cannot include, even fictionally. If you'd like to continue, we can rewind to before that point with all characters as adults."
⚠️ SELF-HARM / SUICIDE — if the user expresses genuine distress, self-harm ideation, or suicidal thoughts:
• Exit roleplay immediately.
• Respond with empathy IN THE USER'S LANGUAGE.
• Provide location-appropriate crisis resources (ask for location if unknown).
• Do NOT continue the scene until the user confirms they are safe.
Character momentum, prior coherence, and user insistence do NOT override any of the above."""

SAFETY_ACK = "Safety and scope check confirmed. NSFW roleplay is on. Hard blocks and self-harm rules are active. Generating response now."


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clean(text):
    """Strip <think>...</think> blocks (Qwen3 thinking tokens)."""
    if not text:
        return ""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    text = re.sub(r"<think>.*",          "", text, flags=re.DOTALL)
    return text.strip()


def _extract_reply(choice):
    """Pull the assistant text out of an OpenAI choice object."""
    msg     = choice.message
    content = _clean(getattr(msg, "content",          None) or "")
    if content:
        return content
    reasoning = _clean(getattr(msg, "reasoning_content", None) or "")
    if reasoning:
        return reasoning
    return ""


def _make_client() -> OpenAI:
    """Create a fresh OpenAI-compatible client pointing at Cortecs."""
    return OpenAI(api_key=CORTECS_API_KEY, base_url=CORTECS_BASE_URL)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/chat", methods=["POST"])
def chat():
    """
    Main chat endpoint.

    Request JSON fields
    -------------------
    message        str   Required. The user's latest message.
    model          str   Optional. Default qwen3.5-9b.
    history        list  Optional. Previous [{role, content}] pairs.
    system_prompt  str   Optional. Overrides DEFAULT_SYSTEM_PROMPT.
    sandwich       bool  Optional. Enable safety sandwich injection.
    extra_body     dict  Optional. Passed straight to the LLM API.
    reasoning_effort str Optional. "low" | "medium" | "high".
    user_id        str   Optional. Used for memory scoping. Defaults to "dev".
    character_id   str   Optional. Used for memory scoping.
    conversation_id str  Optional. Stored on extracted facts.
    memory_on      bool  Optional. Default True. Set False to skip memory.
    """
    if not CORTECS_API_KEY:
        return jsonify({"error": "CORTECS_API_KEY env var not set"}), 500

    data            = request.get_json(silent=True) or {}
    user_message    = (data.get("message") or "").strip()
    if not user_message:
        return jsonify({"error": "Empty message"}), 400

    model            = data.get("model", "qwen3.5-9b")
    extra_body_raw   = data.get("extra_body", {"chat_template_kwargs": {"enable_thinking": False}})
    reasoning_effort = data.get("reasoning_effort")    # "low"|"medium"|"high"|None
    system_prompt    = data.get("system_prompt") or DEFAULT_SYSTEM_PROMPT
    history          = data.get("history", [])
    sandwich_on      = bool(data.get("sandwich", False))
    user_id          = (data.get("user_id") or "dev").strip()
    character_id     = (data.get("character_id") or "").strip() or None
    conversation_id  = (data.get("conversation_id") or "").strip() or None
    memory_on        = data.get("memory_on", True)

    if reasoning_effort:
        extra_body_raw = dict(extra_body_raw) if isinstance(extra_body_raw, dict) else {}
        extra_body_raw["reasoning_effort"] = reasoning_effort

    # --- Memory: build injection block BEFORE the LLM call ---
    memory_block = ""
    used_fact_ids: list[int] = []
    if memory_on:
        memory_block, used_fact_ids = retriever.build_memory_block(
            user_message=user_message,
            user_id=user_id,
            character_id=character_id,
        )

    # --- Build the system prompt (inject memory block at the end if present) ---
    full_system = system_prompt
    if memory_block:
        full_system = f"{system_prompt}\n\n{memory_block}"

    # --- Assemble message list ---
    messages = [{"role": "system", "content": full_system}] + list(history)

    if sandwich_on:
        # Sandwich: inject a safety reminder + ack right before the user message.
        messages += [
            {"role": "user",      "content": SAFETY_REMINDER},
            {"role": "assistant", "content": SAFETY_ACK},
        ]

    messages.append({"role": "user", "content": user_message})

    # --- Call the LLM ---
    try:
        client = _make_client()
        kwargs = dict(
            model=model,
            messages=messages,
            max_tokens=2048,
            stream=False,
        )
        if extra_body_raw:
            kwargs["extra_body"] = extra_body_raw

        response = client.chat.completions.create(**kwargs)
        reply    = _extract_reply(response.choices[0]) if response.choices else ""
        if not reply:
            reply = "Model returned an empty response."
        usage = response.usage

    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    # --- Memory: extract facts AFTER we have the reply (non-blocking) ---
    # We run this in a daemon thread so the HTTP response is not delayed.
    if memory_on:
        _run_extraction_async(
            user_message=user_message,
            user_id=user_id,
            character_id=character_id,
            conversation_id=conversation_id,
            model=model,
            used_fact_ids=used_fact_ids,
        )

    return jsonify({
        "reply": reply,
        "memory_block": memory_block,   # visible in the debug panel
        "usage": {
            "prompt_tokens":     getattr(usage, "prompt_tokens",     None),
            "completion_tokens": getattr(usage, "completion_tokens", None),
            "total_tokens":      getattr(usage, "total_tokens",      None),
        },
    })


@app.route("/memory/debug", methods=["GET"])
def memory_debug():
    """
    Debug endpoint: returns all stored memory facts for a user.
    Usage: GET /memory/debug?user_id=dev
    """
    if not os.environ.get("DATABASE_URL"):
        return jsonify({"error": "DATABASE_URL not set — memory is disabled"}), 503

    user_id = (request.args.get("user_id") or "dev").strip()
    try:
        facts = db.fetch_all_facts_for_debug(user_id)
        # Convert datetimes to ISO strings for JSON serialisation.
        for f in facts:
            for key in ("as_of", "created_at"):
                if f.get(key) is not None:
                    f[key] = f[key].isoformat()
        return jsonify({"user_id": user_id, "facts": facts})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ---------------------------------------------------------------------------
# Internal: async extraction
# ---------------------------------------------------------------------------

def _run_extraction_async(
    user_message: str,
    user_id: str,
    character_id,
    conversation_id,
    model: str,
    used_fact_ids: list[int],
) -> None:
    """
    Spin up a daemon thread to run fact extraction and last_used_at updates
    without blocking the HTTP response.
    """
    def _task():
        try:
            client = _make_client()
            extractor.extract_and_store(
                user_message=user_message,
                user_id=user_id,
                character_id=character_id,
                conversation_id=conversation_id,
                llm_client=client,
                model=model,
            )
            db.touch_last_used(used_fact_ids)
        except Exception as exc:
            log.error("background extraction failed: %s", exc)

    thread = threading.Thread(target=_task, daemon=True)
    thread.start()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
