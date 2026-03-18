import os
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    session,
    g,
)
from werkzeug.security import generate_password_hash, check_password_hash
from mistralai.client import Mistral
from mistralai.client.models import UserMessage

from database import SessionLocal
from models import User, ChatMessage

# -----------------------------------
# Flask setup
# -----------------------------------

app = Flask(__name__, template_folder="templates")
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-change-me")

MISTRAL_API_KEY = os.environ.get("MISTRAL_API_KEY", "")
AGENT_ID = "ag_019cf8b9404e73c7ad980dfc212fbd26"

COIN_PACKS = {
    "small": {
        "coins": 5000,
        "price_kes": 70,
        "label": "Small pack (5,000 coins ≈ 3–4 message pairs, KES 70)",
    },
    "regular": {
        "coins": 30000,
        "price_kes": 300,
        "label": "Regular pack (30,000 coins ≈ 20 message pairs, KES 300)",
    },
    "heavy": {
        "coins": 80000,
        "price_kes": 700,
        "label": "Heavy-use pack (80,000 coins ≈ 50+ message pairs, KES 700)",
    },
}


# -----------------------------------
# DB session per request
# -----------------------------------

@app.before_request
def create_session():
    g.db = SessionLocal()


@app.teardown_request
def close_session(exception=None):
    db = getattr(g, "db", None)
    if db is not None:
        db.close()


# -----------------------------------
# Mistral client helper
# -----------------------------------

def get_mistral_client() -> Mistral:
    return Mistral(api_key=MISTRAL_API_KEY)


# -----------------------------------
# Auth helpers
# -----------------------------------

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def get_current_user(db):
    user_id = session.get("user_id")
    if not user_id:
        return None
    return db.query(User).filter(User.id == user_id).first()


# -----------------------------------
# Routes: auth
# -----------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        db = g.db
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        gender = request.form.get("gender", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        errors = []

        if not username or not email or not password:
            errors.append("Username, email and password are required.")
        if password != confirm:
            errors.append("Passwords do not match.")

        existing = db.query(User).filter(User.username == username).first()
        if existing:
            errors.append("Username already taken.")

        if errors:
            return render_template(
                "register.html",
                errors=errors,
                username=username,
                email=email,
                gender=gender,
            )

        user = User(
            username=username,
            password_hash=generate_password_hash(password),
        )
        user.email = email
        user.gender = gender
        user.coins = 10000  # start with 10000 coins

        db.add(user)
        db.commit()
        db.refresh(user)

        session["user_id"] = str(user.id)
        return redirect(url_for("index"))

    return render_template("register.html", errors=[])


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        db = g.db
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = db.query(User).filter(User.username == username).first()
        if not user or not check_password_hash(user.password_hash, password):
            return render_template(
                "login.html",
                error="Invalid username or password.",
                username=username,
            )

        session["user_id"] = str(user.id)
        return redirect(url_for("index"))

    return render_template("login.html", error=None)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# -----------------------------------
# Routes: main chat
# -----------------------------------

@app.route("/")
@login_required
def index():
    db = g.db
    user = get_current_user(db)
    if not user:
        return redirect(url_for("login"))

    return render_template(
        "index.html",
        username=user.username,
        coins=user.coins,
    )


@app.route("/chat", methods=["POST"])
@login_required
def chat():
    db = g.db
    user = get_current_user(db)
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    # Block if no coins left
    if user.coins <= 0:
        return jsonify(
            {"error": "You have no coins left. Please buy more to continue."}
        ), 403

    data = request.get_json(silent=True) or {}
    user_message = data.get("message", "")
    if not user_message:
        return jsonify({"error": "No message provided"}), 400

    if not MISTRAL_API_KEY:
        return jsonify({"error": "MISTRAL_API_KEY not set"}), 500

    try:
        # Store user message in DB (encrypted)
        user_msg = ChatMessage(user_id=user.id, role="user")
        user_msg.content = user_message
        db.add(user_msg)
        db.commit()
        db.refresh(user_msg)

        client = get_mistral_client()
        response = client.agents.complete(
            messages=[UserMessage(content=user_message)],
            agent_id=AGENT_ID,
            max_tokens=512,
        )

        # Extract reply
        reply = ""
        if getattr(response, "choices", None):
            msg = response.choices[0].message
            content = getattr(msg, "content", "")
            if isinstance(content, str):
                reply = content
            elif isinstance(content, list):
                reply = "".join(str(part) for part in content if part)

        # Extract usage, if provided
        usage = getattr(response, "usage", None)
        prompt_tokens = getattr(usage, "prompt_tokens", None) if usage else None
        completion_tokens = getattr(usage, "completion_tokens", None) if usage else None
        total_tokens = getattr(usage, "total_tokens", None) if usage else None

        if not reply:
            reply = "Agent returned an empty response."

        # Deduct coins: naive rule = coins -= total_tokens (or 1 if None)
        cost = total_tokens if isinstance(total_tokens, int) and total_tokens > 0 else 1
        new_balance = user.coins - cost
        if new_balance < 0:
            new_balance = 0
        user.coins = new_balance

        # Store agent reply in DB (encrypted)
        agent_msg = ChatMessage(user_id=user.id, role="agent")
        agent_msg.content = reply
        db.add(agent_msg)
        db.commit()
        db.refresh(agent_msg)
        db.refresh(user)  # refresh coins

        return jsonify(
            {
                "reply": reply,
                "usage": {
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                    "total_tokens": total_tokens,
                },
                "coins": user.coins,
            }
        )

    except Exception as e:
        print("Error in /chat:", repr(e))
        return jsonify({"error": f"Backend error: {e}"}), 500


# -----------------------------------
# Routes: buy coins
# -----------------------------------

@app.route("/buy-coins", methods=["POST"])
@login_required
def buy_coins():
    db = g.db
    user = get_current_user(db)
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json(silent=True) or {}
    amount = data.get("amount")

    try:
        amount = int(amount)
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid amount"}), 400

    if amount <= 0:
        return jsonify({"error": "Amount must be positive"}), 400

    # Optional safety cap
    if amount > 1000000:
        return jsonify({"error": "Amount too large"}), 400

    current = user.coins
    user.coins = current + amount
    db.commit()
    db.refresh(user)

    return jsonify({"coins": user.coins})


@app.route("/buy-pack", methods=["POST"])
@login_required
def buy_pack():
    db = g.db
    user = get_current_user(db)
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json(silent=True) or {}
    pack_id = (data.get("pack") or "").strip()

    pack = COIN_PACKS.get(pack_id)
    if not pack:
        return jsonify({"error": "Invalid pack id"}), 400

    # For now, no real payment – just credit the coins.
    coins_to_add = pack["coins"]
    user.coins = user.coins + coins_to_add
    db.commit()
    db.refresh(user)

    return jsonify({
        "coins": user.coins,
        "pack": pack_id,
        "coins_added": coins_to_add,
        "price_kes": pack["price_kes"],
    })


# -----------------------------------
# Main
# -----------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
