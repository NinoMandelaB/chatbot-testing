import os
import re
from flask import Flask, request, jsonify, render_template
from openai import OpenAI

app = Flask(__name__)

CORTECS_API_KEY  = os.environ.get("CORTECS_API_KEY", "")
CORTECS_BASE_URL = os.environ.get("CORTECS_BASE_URL", "https://api.cortecs.ai/v1")
SYSTEM_PROMPT    = os.environ.get("SYSTEM_PROMPT", "You are a helpful assistant.")


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
    history          = data.get("history", [])

    # Merge reasoning_effort into extra_body if provided
    if reasoning_effort:
        extra_body_raw = dict(extra_body_raw) if isinstance(extra_body_raw, dict) else {}
        extra_body_raw["reasoning_effort"] = reasoning_effort

    messages = (
        [{"role": "system", "content": SYSTEM_PROMPT}]
        + list(history)
        + [{"role": "user", "content": user_message}]
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
