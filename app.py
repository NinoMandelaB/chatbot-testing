import os
import uuid
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
    make_response,
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

GUEST_INITIAL_COINS = 5000
REGISTERED_INITIAL_COINS = 15000
GUEST_COOKIE = "guest_token"

COIN_PACKS = {
    "small":   {"coins": 5000,  "price_kes": 70,  "label": "Small pack"},
    "regular": {"coins": 30000, "price_kes": 300, "label": "Regular pack"},
    "heavy":   {"coins": 80000, "price_kes": 700, "label": "Heavy-use pack"},
}


# -----------------------------------
# DB session per request
# -----------------------------------

@app.before_request
def create_db_session():
    g.db = SessionLocal()


@app.teardown_request
def close_db_session(exception=None):
    db = getattr(g, "db", None)
    if db is not None:
        db.close()


# -----------------------------------
# Mistral client helper
# -----------------------------------

def get_mistral_client() -> Mistral:
    return Mistral(api_key=MISTRAL_API_KEY)


# -----------------------------------
# Auth / guest helpers
# -----------------------------------

def get_current_user(db):
    user_id = session.get("user_id")
    if not user_id:
        return None
    return db.query(User).filter(User.id == user_id).first()


def get_guest_coins():
    """Returns (coins, token_or_False).
    If brand new guest: returns (GUEST_INITIAL_COINS, new_token_string).
    If returning guest: returns (current_coins, False).
    """
    token = request.cookies.get(GUEST_COOKIE)
    if token:
        coins = session.get(f"guest_coins_{token}")
        if coins is None:
            # Cookie exists but session lost – reset
            session[f"guest_coins_{token}"] = GUEST_INITIAL_COINS
            return GUEST_INITIAL_COINS, token
        return coins, False
    else:
        token = str(uuid.uuid4())
        session[f"guest_coins_{token}"] = GUEST_INITIAL_COINS
        return GUEST_INITIAL_COINS, token


def set_guest_coins(token, coins):
    session[f"guest_coins_{token}"] = coins


# -----------------------------------
# Routes: auth
# -----------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        db = g.db
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip()
        gender   = request.form.get("gender", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm", "")

        errors = []
        if not username or not email or not password:
            errors.append("Username, email and password are required.")
        if password != confirm:
            errors.append("Passwords do not match.")
        if db.query(User).filter(User.username == username).first():
            errors.append("Username already taken.")

        if errors:
            return render_template(
                "register.html", errors=errors,
                username=username, email=email, gender=gender,
                registered_coins=REGISTERED_INITIAL_COINS,
            )

        user = User(username=username, password_hash=generate_password_hash(password))
        user.email  = email
        user.gender = gender
        user.coins  = REGISTERED_INITIAL_COINS

        db.add(user)
        db.commit()
        db.refresh(user)

        session["user_id"] = str(user.id)
        token = request.cookies.get(GUEST_COOKIE)
        if token:
            session.pop(f"guest_coins_{token}", None)

        resp = make_response(redirect(url_for("index")))
        resp.delete_cookie(GUEST_COOKIE)
        return resp

    return render_template("register.html", errors=[],
                           registered_coins=REGISTERED_INITIAL_COINS)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        db = g.db
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = db.query(User).filter(User.username == username).first()
        if not user or not check_password_hash(user.password_hash, password):
            return render_template("login.html",
                                   error="Invalid username or password.",
                                   username=username)

        session["user_id"] = str(user.id)
        token = request.cookies.get(GUEST_COOKIE)
        if token:
            session.pop(f"guest_coins_{token}", None)

        resp = make_response(redirect(url_for("index")))
        resp.delete_cookie(GUEST_COOKIE)
        return resp

    return render_template("login.html", error=None)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# -----------------------------------
# Routes: main (guest + logged-in)
# -----------------------------------

@app.route("/")
def index():
    db  = g.db
    user = get_current_user(db)

    if user:
        return render_template("index.html",
                               username=user.username,
                               coins=user.coins,
                               is_guest=False)

    # Guest
    coins, new_token = get_guest_coins()
    resp = make_response(render_template("index.html",
                                         username="Guest",
                                         coins=coins,
                                         is_guest=True))
    if new_token:
        resp.set_cookie(GUEST_COOKIE, new_token,
                        max_age=60 * 60 * 24 * 30,
                        httponly=True, samesite="Lax")
    return resp


@app.route("/chat", methods=["POST"])
def chat():
    db   = g.db
    user = get_current_user(db)
    is_guest    = user is None
    guest_token = request.cookies.get(GUEST_COOKIE) if is_guest else None

    # Check coins
    if is_guest:
        coins = session.get(f"guest_coins_{guest_token}", 0) if guest_token else 0
        if coins <= 0:
            return jsonify({"error": "no_coins"}), 403
    else:
        if user.coins <= 0:
            return jsonify({"error": "no_coins"}), 403

    data         = request.get_json(silent=True) or {}
    user_message = data.get("message", "")
    if not user_message:
        return jsonify({"error": "No message provided"}), 400
    if not MISTRAL_API_KEY:
        return jsonify({"error": "MISTRAL_API_KEY not set"}), 500

    try:
        if not is_guest:
            user_msg         = ChatMessage(user_id=user.id, role="user")
            user_msg.content = user_message
            db.add(user_msg)
            db.commit()

        client   = get_mistral_client()
        response = client.agents.complete(
            messages=[UserMessage(content=user_message)],
            agent_id=AGENT_ID, max_tokens=512,
        )

        reply = ""
        if getattr(response, "choices", None):
            msg     = response.choices[0].message
            content = getattr(msg, "content", "")
            if isinstance(content, str):
                reply = content
            elif isinstance(content, list):
                reply = "".join(str(p) for p in content if p)

        usage             = getattr(response, "usage", None)
        prompt_tokens     = getattr(usage, "prompt_tokens",     None) if usage else None
        completion_tokens = getattr(usage, "completion_tokens", None) if usage else None
        total_tokens      = getattr(usage, "total_tokens",      None) if usage else None

        if not reply:
            reply = "Agent returned an empty response."

        cost = total_tokens if isinstance(total_tokens, int) and total_tokens > 0 else 1

        if is_guest:
            current_coins = max(0, coins - cost)
            set_guest_coins(guest_token, current_coins)
        else:
            current_coins = max(0, user.coins - cost)
            user.coins    = current_coins
            agent_msg         = ChatMessage(user_id=user.id, role="agent")
            agent_msg.content = reply
            db.add(agent_msg)
            db.commit()
            db.refresh(user)

        return jsonify({
            "reply": reply,
            "usage": {
                "prompt_tokens":     prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens":      total_tokens,
            },
            "coins":    current_coins,
            "is_guest": is_guest,
        })

    except Exception as e:
        print("Error in /chat:", repr(e))
        return jsonify({"error": f"Backend error: {e}"}), 500


# -----------------------------------
# Routes: buy coins / packs (logged-in only)
# -----------------------------------

@app.route("/buy-coins", methods=["POST"])
def buy_coins():
    db   = g.db
    user = get_current_user(db)
    if not user:
        return jsonify({"error": "Login required to buy coins"}), 401

    data   = request.get_json(silent=True) or {}
    amount = data.get("amount")
    try:
        amount = int(amount)
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid amount"}), 400

    if amount <= 0:
        return jsonify({"error": "Amount must be positive"}), 400
    if amount > 1000000:
        return jsonify({"error": "Amount too large"}), 400

    user.coins += amount
    db.commit()
    db.refresh(user)
    return jsonify({"coins": user.coins})


@app.route("/buy-pack", methods=["POST"])
def buy_pack():
    db   = g.db
    user = get_current_user(db)
    if not user:
        return jsonify({"error": "Login required to buy packs"}), 401

    data    = request.get_json(silent=True) or {}
    pack_id = (data.get("pack") or "").strip()
    pack    = COIN_PACKS.get(pack_id)
    if not pack:
        return jsonify({"error": "Invalid pack id"}), 400

    user.coins += pack["coins"]
    db.commit()
    db.refresh(user)

    return jsonify({
        "coins":       user.coins,
        "pack":        pack_id,
        "coins_added": pack["coins"],
        "price_kes":   pack["price_kes"],
    })


# -----------------------------------
# Main
# -----------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
