import os
from flask import Flask, render_template, request, jsonify
from mistralai import Mistral
from mistralai.models import UserMessage  # message helper for agents.complete[web:44]

app = Flask(__name__)

MISTRAL_API_KEY = os.environ.get("MISTRAL_API_KEY", "")
AGENT_ID = "ag_019cf8b9404e73c7ad980dfc212fbd26"


def get_client() -> Mistral:
    # Simple helper to create a client; for a tiny app this is fine.[web:2][web:46]
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

        # Use the Agents SDK: agents.complete with your agent id.[web:42][web:44][web:46]
        response = client.agents.complete(
            messages=[UserMessage(content=user_message)],
            agent_id=AGENT_ID,
            max_tokens=512,
        )

        # The response has .choices[0].message.content, like chat completions.[web:42][web:44]
        reply = ""
        if getattr(response, "choices", None):
            msg = response.choices[0].message
            # msg.content can be a string or list; handle both.[web:44]
            content = getattr(msg, "content", "")
            if isinstance(content, str):
                reply = content
            elif isinstance(content, list):
                reply = "".join(str(part) for part in content if part)

        if not reply:
            reply = "Agent returned an empty response."

        return jsonify({"reply": reply})

    except Exception as e:
        # Log to stdout for Railway logs
        print("Error calling Mistral agents.complete:", repr(e))
        return jsonify({"error": f"Backend error: {e}"}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
