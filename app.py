import os
import re
from flask import Flask, request, jsonify, render_template
from openai import OpenAI

app = Flask(__name__)

CORTECS_API_KEY  = os.environ.get("CORTECS_API_KEY", "")
CORTECS_BASE_URL = os.environ.get("CORTECS_BASE_URL", "https://api.cortecs.ai/v1")
DEFAULT_SYSTEM_PROMPT = os.environ.get("SYSTEM_PROMPT", "You are a helpful assistant.")

# Injected silently before every user message (sandwich method).
# Keeps hard blocks fresh at the bottom of the context window regardless of history length.
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


def _clean(text):
    """Strip <think>...</think> blocks (Qwen3 thinking tokens)."""
    if not text:
        return ""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    text = re.sub(r"<think>.*", "", text, flags=re.DOTALL)
    return text.strip()


def extract_reply(choice):
    msg = choice.message
    content = _clean(getattr(msg, "content", None) or "")
    if content:
        return content
    reasoning = _clean(getattr(msg, "reasoning_content", None) or "")
    if reasoning:
        return reasoning
    return ""


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/chat", methods=["POST"])
def chat():
    if not CORTECS_API_KEY:
        return jsonify({"error": "CORTECS_API_KEY env var not set"}), 500

    data = request.get_json(silent=True) or {}
    user_message = (data.get("message") or "").strip()
    if not user_message:
        return jsonify({"error": "Empty message"}), 400

    model            = data.get("model", "qwen3.5-9b")
    extra_body_raw   = data.get("extra_body", {"chat_template_kwargs": {"enable_thinking": False}})
    reasoning_effort = data.get("reasoning_effort")  # "low" | "medium" | "high" | None
    system_prompt    = data.get("system_prompt") or DEFAULT_SYSTEM_PROMPT
    history          = data.get("history", [])

    if reasoning_effort:
        extra_body_raw = dict(extra_body_raw) if isinstance(extra_body_raw, dict) else {}
        extra_body_raw["reasoning_effort"] = reasoning_effort

    # Sandwich: system prompt → history → safety reminder → ack → current user message
    messages = (
        [{"role": "system",    "content": system_prompt}]
        + list(history)
        + [{"role": "user",      "content": SAFETY_REMINDER},
           {"role": "assistant", "content": SAFETY_ACK},
           {"role": "user",      "content": user_message}]
    )

    try:
        client = OpenAI(api_key=CORTECS_API_KEY, base_url=CORTECS_BASE_URL)
        kwargs = dict(model=model, messages=messages, max_tokens=2048, stream=False)
        if extra_body_raw:
            kwargs["extra_body"] = extra_body_raw

        response = client.chat.completions.create(**kwargs)
        reply = extract_reply(response.choices[0]) if response.choices else ""
        if not reply:
            reply = "Model returned an empty response."

        usage = response.usage
        return jsonify({
            "reply": reply,
            "usage": {
                "prompt_tokens":     getattr(usage, "prompt_tokens", None),
                "completion_tokens": getattr(usage, "completion_tokens", None),
                "total_tokens":      getattr(usage, "total_tokens", None),
            },
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
