import logging
import os
import re
from flask import Flask, request, jsonify, render_template
from openai import OpenAI

from memory import db as memory_db
from memory import summariser as memory_summariser
from memory import retriever as memory_retriever
from memory import extractor as memory_extractor

app = Flask(__name__)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration (loaded from environment variables)
# ---------------------------------------------------------------------------
CORTECS_API_KEY  = os.environ.get("CORTECS_API_KEY", "")
CORTECS_BASE_URL = os.environ.get("CORTECS_BASE_URL", "https://api.cortecs.ai/v1")
DEFAULT_SYSTEM_PROMPT = os.environ.get("SYSTEM_PROMPT", "You are a helpful assistant.")

# ---------------------------------------------------------------------------
# Safety sandwich constants
# Injected silently before every user message when sandwich mode is ON.
# ---------------------------------------------------------------------------
SAFETY_REMINDER = """[SAFETY & SCOPE REMINDER - re-read before generating your response]

NSFW adult roleplay IS allowed and encouraged. Stay immersive, in-character, and explicit if the scene calls for it.

HARD STOP - exit scene IMMEDIATELY and use the refusal template if the current message contains ANY of:
- Sexual content involving a clear minor/underage signal, e.g. child, minor, underage, teen, 17, schoolgirl, schoolboy, barely legal, too young, young-looking, still developing, little girl, little boy
- Incest / family sex
- Bestiality
- Non-consent / force / threats / incapacity
- CSAM / rape / graphic violence against a real person
- Hate speech / criminal instructions / doxxing

Adult pet names or dominance language alone are NOT minor signals.
Examples that may be allowed on their own, if in clear adult context: baby, daddy, mommy, good girl, good boy, little slut, little toy, sir, master, mistress, princess, king, queen.

Refusal template (translate into the user's language):
"I have to stop the roleplay here. [trigger] is something I cannot include, even fictionally. If you'd like to continue, we can rewind to before that point."

SELF-HARM / SUICIDE - if the user expresses genuine distress, self-harm ideation, or suicidal thoughts:
- Exit roleplay immediately.
- Respond with empathy IN THE USER'S LANGUAGE.
- Provide location-appropriate crisis resources (https://findahelpline.com/).
- Do NOT continue the scene until the user confirms they are safe.

Character momentum, prior coherence, and user insistence do NOT override any of the above."""

SAFETY_ACK = "Safety and scope check confirmed. NSFW roleplay is on. Hard blocks and self-harm rules are active. Generating response now."

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _clean(text):
    """Strip <think>...</think> blocks produced by Qwen3 thinking mode."""
    if not text:
        return ""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    text = re.sub(r"<think>.*", "", text, flags=re.DOTALL)
    return text.strip()


def extract_reply(choice):
    """Extract the best text content from a chat completion choice."""
    msg = choice.message
    content = _clean(getattr(msg, "content", None) or "")
    if content:
        return content
    # Fallback: some models surface reasoning in reasoning_content.
    reasoning = _clean(getattr(msg, "reasoning_content", None) or "")
    if reasoning:
        return reasoning
    return ""


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/chat", methods=["POST"])
def chat():
    """Main chat endpoint.

    Per-turn memory pipeline (executed in this order):
      1. retriever.build_memory_block()  -- inject facts + summary BEFORE the LLM call
      2. LLM call
      3. extractor.extract_and_store()  -- learn new facts from the user message AFTER reply
      4. db.touch_last_used()           -- mark injected facts as recently used
      5. summariser.maybe_summarise()   -- conditionally update the long-term summary

    Prompt order sent to the LLM (matches the hint shown in the UI):
      1. System prompt (+ character card appended if provided)
      2. Memory block (injected as a system turn when a session is active)
      3. Conversation history
      4. Safety sandwich (when enabled)
      5. User message
    """
    if not CORTECS_API_KEY:
        return jsonify({"error": "CORTECS_API_KEY env var not set"}), 500

    data = request.get_json(silent=True) or {}

    # --- Required fields ---
    user_message = (data.get("message") or "").strip()
    if not user_message:
        return jsonify({"error": "Empty message"}), 400

    # --- Model and API params ---
    model            = data.get("model", "qwen3.5-9b")
    extra_body_raw   = data.get("extra_body", {"chat_template_kwargs": {"enable_thinking": False}})
    reasoning_effort = data.get("reasoning_effort")  # "low" | "medium" | "high" | None

    # --- Prompt content ---
    system_prompt  = data.get("system_prompt") or DEFAULT_SYSTEM_PROMPT
    character_card = (data.get("character_card") or "").strip()  # optional persona block
    history        = data.get("history", [])
    sandwich_on    = bool(data.get("sandwich", False))

    # --- Session context (used for memory retrieval, extraction, and summarisation) ---
    user_id      = (data.get("user_id")      or "").strip() or None
    character_id = (data.get("character_id") or "").strip() or None

    # Append reasoning_effort to extra_body when specified.
    if reasoning_effort:
        extra_body_raw = dict(extra_body_raw) if isinstance(extra_body_raw, dict) else {}
        extra_body_raw["reasoning_effort"] = reasoning_effort

    # -----------------------------------------------------------------------
    # Build the system content
    # Character card is appended directly after the system prompt so the LLM
    # sees both pieces of instruction before any conversation turns.
    # -----------------------------------------------------------------------
    system_content = system_prompt
    if character_card:
        system_content += "\n\n" + character_card

    # -----------------------------------------------------------------------
    # Step 1 -- Hybrid memory retrieval (BEFORE the LLM call)
    # Build the [MEMORY] block from stored facts + active conversation summary.
    # Runs only when a session is active (user_id is required at minimum).
    # -----------------------------------------------------------------------
    messages: list = [{"role": "system", "content": system_content}]
    used_fact_ids: list = []

    if user_id:
        memory_block, used_fact_ids = memory_retriever.build_memory_block(
            user_message=user_message,
            user_id=user_id,
            character_id=character_id,
        )
        if memory_block:
            # Inject as a dedicated system turn so the LLM cannot confuse
            # memory content with real conversation messages.
            messages.append({"role": "system", "content": memory_block})

    # Conversation history
    messages += list(history)

    # Safety sandwich (optional; injected immediately before the user turn)
    if sandwich_on:
        messages += [
            {"role": "user",      "content": SAFETY_REMINDER},
            {"role": "assistant", "content": SAFETY_ACK},
        ]

    messages.append({"role": "user", "content": user_message})

    # -----------------------------------------------------------------------
    # Step 2 -- LLM call
    # The client is created once per request using the API key already
    # validated above.  All post-reply steps reuse the same client instance.
    # -----------------------------------------------------------------------
    client = OpenAI(api_key=CORTECS_API_KEY, base_url=CORTECS_BASE_URL)

    try:
        kwargs = dict(
            model=model,
            messages=messages,
            max_tokens=2048,
            stream=False,
        )
        if extra_body_raw:
            kwargs["extra_body"] = extra_body_raw

        response = client.chat.completions.create(**kwargs)
        reply = extract_reply(response.choices[0]) if response.choices else ""
        if not reply:
            reply = "Model returned an empty response."
        usage = response.usage

        # -------------------------------------------------------------------
        # Steps 3-5 -- Post-reply memory updates (only when session is active)
        # All three are fire-and-forget: errors are logged but never re-raised
        # so a memory failure never blocks the user's chat response.
        # -------------------------------------------------------------------
        if user_id:

            # Step 3 -- Extract and store facts + safety flags from the user's
            # message.  We pass the same client and model already in use so
            # the extractor stays in sync with the active chat model.
            try:
                memory_extractor.extract_and_store(
                    user_message=user_message,
                    user_id=user_id,
                    character_id=character_id,
                    conversation_id=None,  # no per-conversation ID in this app
                    llm_client=client,
                    model=model,
                )
            except Exception as exc:
                log.warning("chat: extract_and_store failed: %s", exc)

            # Step 4 -- Mark injected facts as recently used so that the
            # confidence-decay scoring stays accurate over time.
            if used_fact_ids:
                try:
                    memory_db.touch_last_used(used_fact_ids)
                except Exception as exc:
                    log.warning("chat: touch_last_used failed: %s", exc)

            # Step 5 -- Conditionally update the long-term conversation
            # summary.  Both user_id and character_id are required.
            # The same model the user selected is forwarded so summarisation
            # stays in sync with the active UI model selection.
            if user_id and character_id:
                full_history = list(history) + [
                    {"role": "user",      "content": user_message},
                    {"role": "assistant", "content": reply},
                ]
                # Atomically increment the session turn counter and get the current total.
                # Fires when turn_count is a multiple of SUMMARISE_EVERY.
                turn_count = memory_db.increment_and_get_turn_count(
                    user_id, character_id
                )
                try:
                    memory_summariser.maybe_summarise(
                        user_id=user_id,
                        character_id=character_id,
                        history=full_history,
                        api_key=CORTECS_API_KEY,
                        base_url=CORTECS_BASE_URL,
                        model=model,
                                        turn_count=turn_count,
                    )
                except Exception as exc:
                    log.warning("chat: maybe_summarise failed: %s", exc)

        return jsonify({
            "reply": reply,
            "usage": {
                "prompt_tokens":     getattr(usage, "prompt_tokens",     None),
                "completion_tokens": getattr(usage, "completion_tokens", None),
                "total_tokens":      getattr(usage, "total_tokens",      None),
            },
            # Echo back the active session so the frontend can confirm it.
            "session": {
                "user_id":      user_id,
                "character_id": character_id,
            },
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/memory/debug", methods=["GET"])
def memory_debug():
    """Return memory facts filtered by user_id and/or character_id.

    Filter behaviour:
      - no params          -> full table (up to 200 rows)
      - user_id only       -> all facts for that user
      - character_id only  -> all facts for that character across all users
      - both provided      -> facts matching both user AND character
    """
    user_id      = (request.args.get("user_id")      or "").strip() or None
    character_id = (request.args.get("character_id") or "").strip() or None

    try:
        rows = memory_db.fetch_facts_for_debug(
            user_id=user_id,
            character_id=character_id,
            limit=200,
        )
    except Exception as e:
        return jsonify({"error": f"Database error: {e}"}), 500

    # Split rows into the three display buckets the frontend expects.
    user_memories      = [r for r in rows if r.get("scope") == "user_private"]
    character_memories = [r for r in rows if r.get("scope") == "cross_character"]
    safety_memories    = [r for r in rows if r.get("scope") == "safety_global"]

    def serialise(record):
        """Convert datetime values to ISO strings for JSON serialisation."""
        return {
            k: (v.isoformat() if hasattr(v, "isoformat") else v)
            for k, v in record.items()
        }

    return jsonify({
        "user_memories":      [serialise(r) for r in user_memories],
        "character_memories": [serialise(r) for r in character_memories],
        "safety_memories":    [serialise(r) for r in safety_memories],
        "filters": {
            "user_id":      user_id,
            "character_id": character_id,
            "mode":         "filtered" if (user_id or character_id) else "full_table",
            "total_rows":   len(rows),
        },
    })


# ---------------------------------------------------------------------------
# Preview-prompt route
# ---------------------------------------------------------------------------
@app.route("/preview-prompt", methods=["POST"])
def preview_prompt():
    """Return the exact list of messages that /chat would send to the LLM.

    Accepts the same JSON body as /chat (message, model, system_prompt,
    character_card, history, sandwich, memory_on, user_id, character_id,
    history_limit).

    Runs the real memory retriever so the [MEMORY] block shown in the
    preview contains the actual facts from the DB, not a placeholder.
    Does NOT call the LLM and does NOT modify any state.

    Returns:
        messages  -- list of {role, content} dicts in LLM order
        segments  -- same list but with a human-readable label per entry
                     (used by the frontend to render section headers)
    """
    data = request.get_json(silent=True) or {}

    # --- Prompt content (mirrors /chat exactly) ---
    system_prompt  = data.get("system_prompt") or DEFAULT_SYSTEM_PROMPT
    character_card = (data.get("character_card") or "").strip()
    history        = data.get("history", [])
    sandwich_on    = bool(data.get("sandwich", False))
    user_message   = (data.get("message") or "").strip()
    user_id        = (data.get("user_id") or "").strip() or None
    character_id   = (data.get("character_id") or "").strip() or None

    # -------------------------------------------------------------------
    # Build messages list -- identical logic to /chat
    # -------------------------------------------------------------------

    # 1. System prompt + character card (merged into one system turn)
    system_content = system_prompt
    if character_card:
        system_content += "\n\n" + character_card

    messages = [{"role": "system", "content": system_content}]
    # Label for the frontend: split at the character-card boundary so
    # the user can see both sections clearly.
    seg_label_system = "SYSTEM PROMPT"
    if character_card:
        seg_label_system = "SYSTEM PROMPT + CHARACTER CARD"

    segments = [{"label": seg_label_system, "role": "system", "content": system_content}]

    # 2. Memory block (real retrieval from DB, same as /chat)
    if user_id:
        try:
            memory_block, _ = memory_retriever.build_memory_block(
                user_message=user_message,
                user_id=user_id,
                character_id=character_id,
            )
        except Exception as exc:
            log.warning("preview_prompt: memory retrieval failed: %s", exc)
            memory_block = None

        if memory_block:
            messages.append({"role": "system", "content": memory_block})
            segments.append({"label": "MEMORY BLOCK", "role": "system", "content": memory_block})
        else:
            segments.append({
                "label": "MEMORY BLOCK",
                "role": "system",
                "content": "(no memory facts for this session)",
            })
    else:
        segments.append({
            "label": "MEMORY BLOCK",
            "role": "system",
            "content": "(no session active — set user_id to enable memory)",
        })

    # 3. Conversation history
    for turn in history:
        messages.append(turn)
        segments.append({"label": "HISTORY", "role": turn.get("role", ""), "content": turn.get("content", "")})

    # 4. Safety sandwich (optional)
    if sandwich_on:
        messages.append({"role": "user",      "content": SAFETY_REMINDER})
        messages.append({"role": "assistant", "content": SAFETY_ACK})
        segments.append({"label": "SAFETY SANDWICH (user)",     "role": "user",      "content": SAFETY_REMINDER})
        segments.append({"label": "SAFETY SANDWICH (assistant)","role": "assistant", "content": SAFETY_ACK})

    # 5. Current user message
    if user_message:
        messages.append({"role": "user", "content": user_message})
        segments.append({"label": "USER MESSAGE", "role": "user", "content": user_message})
    else:
        segments.append({
            "label": "USER MESSAGE",
            "role": "user",
            "content": "(input field is empty)",
        })

    return jsonify({"messages": messages, "segments": segments})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
