import os
from flask import Flask, render_template, request, jsonify
from mistralai.client import Mistral
from mistralai.client.models import UserMessage

app = Flask(__name__)

MISTRAL_API_KEY = os.environ.get("MISTRAL_API_KEY", "")
AGENT_ID = "ag_019cf8b9404e73c7ad980dfc212fbd26"


def get_client() -> Mistral:
    return Mistral(api_key=MISTRAL_API_KEY)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/chat", methods=["POST"])
def chat():
    data = request.get_json(silent=True) or {}
    user_message = data.get("message", "")
    if not user_message:
        return jsonify({"error": "No message provided"}), 400

    if not MISTRAL_API_KEY:
        return jsonify({"error": "MISTRAL_API_KEY not set"}), 500

    try:
        client = get_client()

        # Call your agent via the SDK
        response = client.agents.complete(
            messages=[UserMessage(content=user_message)],
            agent_id=AGENT_ID,
            max_tokens=512,
        )

        # Extract reply text
        reply = ""
        if getattr(response, "choices", None):
            msg = response.choices[0].message
            content = getattr(msg, "content", "")
            if isinstance(content, str):
                reply = content
            elif isinstance(content, list):
                reply = "".join(str(part) for part in content if part)

        # Extract token usage, if provided by the SDK
        usage = getattr(response, "usage", None)
        prompt_tokens = getattr(usage, "prompt_tokens", None) if usage else None
        completion_tokens = getattr(usage, "completion_tokens", None) if usage else None
        total_tokens = getattr(usage, "total_tokens", None) if usage else None

        if not reply:
            reply = "Agent returned an empty response."

        return jsonify({
            "reply": reply,
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": total_tokens,
            },
        })

    except Exception as e:
        print("Error calling Mistral agents.complete:", repr(e))
        return jsonify({"error": f"Backend error: {e}"}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
