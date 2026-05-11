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

CORTECS_API_KEY      = os.environ.get("CORTECS_API_KEY", "")
CORTECS_BASE_URL     = os.environ.get("CORTECS_BASE_URL", "https://api.cortecs.ai/v1")
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


def _build_system_prompt(
    base_system: str,
    character_card: str,
    memory_block: str,
) -> str:
    """
    Assembles the final system prompt in the correct order:
      1. System prompt  (rules, persona, safety)
      2. Character card (optional — who the character is for THIS session)
      3. Memory facts   (optional — what this character knows about THIS user)

    The safety sandwich is NOT part of the system prompt; it is injected
    into the message list immediately before the user turn (see /chat).
    """
    parts = [base_system.strip()]
    if character_card:
        parts.append("# Character Card\n" + character_card.strip())
    if memory_block:
        parts.append(memory_block.strip())
    return "\n\n".join(parts)


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

    Prompt assembly order
    ---------------------
    1. system_prompt   — base rules + persona
    2. character_card  — character description (optional)
    3. memory block    — retrieved facts about this user (optional)
    [history turns]
    4. sandwich        — safety reminder + ack (optional, right before user msg)
    5. user message

    Request JSON fields
    -------------------
    message          str   Required.
    model            str   Optional. Default qwen3.5-9b.
    history          list  Optional. Previous [{role, content}] pairs.
    system_prompt    str   Optional. Overrides DEFAULT_SYSTEM_PROMPT.
    character_card   str   Optional. Appended after system_prompt, before memory.
    sandwich         bool  Optional. Enable safety sandwich injection.
    extra_body       dict  Optional. Passed straight to the LLM API.
    reasoning_effort str   Optional. "low" | "medium" | "high".
    user_id          str   Optional. Used for memory scoping. Defaults to "dev".
    character_id     str   Optional. Used for memory scoping.
    conversation_id  str   Optional. Stored on extracted facts.
    memory_on        bool  Optional. Default True.
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
    system_prompt    = (data.get("system_prompt") or DEFAULT_SYSTEM_PROMPT).strip()
    character_card   = (data.get("character_card") or "").strip()
    history          = data.get("history", [])
    sandwich_on      = bool(data.get("sandwich", False))
    user_id          = (data.get("user_id") or "dev").strip()
    character_id     = (data.get("character_id") or "").strip() or None
    conversation_id  = (data.get("conversation_id") or "").strip() or None
    memory_on        = data.get("memory_on", True)

    if reasoning_effort:
        extra_body_raw = dict(extra_body_raw) if isinstance(extra_body_raw, dict) else {}
        extra_body_raw["reasoning_effort"] = reasoning_effort

    # ── 1. Memory: build injection block BEFORE the LLM call ─────────────────
    memory_block = ""
    used_fact_ids: list[int] = []
    if memory_on:
        memory_block, used_fact_ids = retriever.build_memory_block(
            user_message=user_message,
            user_id=user_id,
            character_id=character_id,
        )

    # ── 2. Assemble system prompt: base → character card → memory ─────────────
    full_system = _build_system_prompt(
        base_system=system_prompt,
        character_card=character_card,
        memory_block=memory_block,
    )

    # ── 3. Assemble message list ───────────────────────────────────────────────
    messages = [{"role": "system", "content": full_system}] + list(history)

    if sandwich_on:
        # Safety sandwich: injected right before the user message so the
        # safety rules are the last thing in context before generation.
        messages += [
            {"role": "user",      "content": SAFETY_REMINDER},
            {"role": "assistant", "content": SAFETY_ACK},
        ]

    messages.append({"role": "user", "content": user_message})

    # ── 4. Call the LLM ───────────────────────────────────────────────────────
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

    # ── 5. Memory: extract facts AFTER reply (non-blocking) ───────────────────
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
        "memory_block": memory_block,
        "usage": {
            "prompt_tokens":     getattr(usage, "prompt_tokens",     None),
            "completion_tokens": getattr(usage, "completion_tokens", None),
            "total_tokens":      getattr(usage, "total_tokens",      None),
        },
    })


@app.route("/memory/debug", methods=["GET"])
def memory_debug():
    """
    Debug endpoint — returns stored memory facts split by scope.
    GET /memory/debug?user_id=dev&character_id=char_test
    """
    if not os.environ.get("DATABASE_URL"):
        return jsonify({"error": "DATABASE_URL not set — memory is disabled"}), 503

    user_id      = (request.args.get("user_id")      or "dev").strip()
    character_id = (request.args.get("character_id") or "").strip() or None

    try:
        facts = db.fetch_all_facts_for_debug(user_id)
        for f in facts:
            for key in ("as_of", "created_at", "updated_at", "last_used_at"):
                if f.get(key) is not None:
                    f[key] = f[key].isoformat()

        # Split by scope so the UI can show them in separate sections.
        # user_private  → belongs only to this user, scoped to one character.
        # character_private → what a character has "learned" (NOT shared across characters).
        # safety_global → cross-character safety flags ONLY.
        user_memories      = [f for f in facts if f.get("scope") == "user_private"
                               and (character_id is None or f.get("character_id") == character_id)]
        character_memories = [f for f in facts if f.get("scope") == "character_private"
                               and (character_id is None or f.get("character_id") == character_id)]
        safety_memories    = [f for f in facts if f.get("scope") == "safety_global"]

        # Normalise key for display
        def _normalise(lst):
            return [{"fact": f.get("fact_text", ""), **f} for f in lst]

        return jsonify({
            "user_id":            user_id,
            "user_memories":      _normalise(user_memories),
            "character_memories": _normalise(character_memories),
            "safety_memories":    _normalise(safety_memories),
        })
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

    threading.Thread(target=_task, daemon=True).start()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
