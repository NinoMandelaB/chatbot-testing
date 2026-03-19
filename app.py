import os
import uuid
import hmac
import hashlib
import requests as http_requests

import redis as redis_lib

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
from models import User, ChatMessage, CoinTransaction

# -----------------------------------
# Flask setup
# -----------------------------------

app = Flask(__name__, template_folder="templates")
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-change-me")

MISTRAL_API_KEY     = os.environ.get("MISTRAL_API_KEY", "")
AGENT_ID            = "ag_019cf8b9404e73c7ad980dfc212fbd26"
PAYSTACK_SECRET_KEY = os.environ.get("PAYSTACK_SECRET_KEY", "")
PAYSTACK_PUBLIC_KEY = os.environ.get("PAYSTACK_PUBLIC_KEY", "")

GUEST_INITIAL_COINS      = 5000
REGISTERED_INITIAL_COINS = 15000
GUEST_COOKIE             = "guest_token"
GUEST_TTL                = 60 * 60 * 24 * 30

COIN_PACKS = {
    "small":   {"coins": 5000,  "price_kes": 70,  "label": "Small pack"},
    "regular": {"coins": 30000, "price_kes": 300, "label": "Regular pack"},
    "heavy":   {"coins": 80000, "price_kes": 700, "label": "Heavy-use pack"},
}

PAYSTACK_HEADERS = lambda: {
    "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
    "Content-Type": "application/json",
}

# -----------------------------------
# Redis (guest coins)
# -----------------------------------

_redis_client = None

def get_redis():
    global _redis_client
    if _redis_client is None:
        url = os.environ.get("REDIS_URL", "redis://localhost:6379")
        _redis_client = redis_lib.from_url(url, decode_responses=True)
    return _redis_client

def redis_guest_key(guest_id): return f"guest_coins:{guest_id}"

def get_guest_coins_redis(guest_id):
    r, key = get_redis(), redis_guest_key(guest_id)
    val    = r.get(key)
    if val is None:
        r.setex(key, GUEST_TTL, GUEST_INITIAL_COINS)
        return GUEST_INITIAL_COINS
    r.expire(key, GUEST_TTL)
    return int(val)

def set_guest_coins_redis(guest_id, coins):
    r = get_redis()
    r.setex(redis_guest_key(guest_id), GUEST_TTL, max(0, coins))

# -----------------------------------
# DB session per request
# -----------------------------------

@app.before_request
def create_db_session():
    g.db = SessionLocal()

@app.teardown_request
def close_db_session(exception=None):
    db = getattr(g, "db", None)
    if db:
        db.close()

# -----------------------------------
# Helpers
# -----------------------------------

def get_mistral_client():
    return Mistral(api_key=MISTRAL_API_KEY)

def get_current_user(db):
    user_id = session.get("user_id")
    if not user_id:
        return None
    return db.query(User).filter(User.id == user_id).first()

def log_transaction(db, user, delta, reason):
    tx        = CoinTransaction(user_id=user.id)
    tx.delta  = delta
    tx.reason = reason
    db.add(tx)

# -----------------------------------
# Routes: auth
# -----------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        db       = g.db
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip()
        gender   = request.form.get("gender", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm", "")

        # E2EE fields from JS (generated in browser before form submit)
        kdf_salt               = request.form.get("kdf_salt", "").strip()
        encrypted_dek          = request.form.get("encrypted_dek", "").strip()
        recovery_encrypted_dek = request.form.get("recovery_encrypted_dek", "").strip()

        errors = []
        if not username or not email or not password:
            errors.append("Username, email and password are required.")
        if password != confirm:
            errors.append("Passwords do not match.")
        if db.query(User).filter(User.username == username).first():
            errors.append("Username already taken.")
        if not kdf_salt or not encrypted_dek or not recovery_encrypted_dek:
            errors.append("Encryption setup failed — please try again.")

        if errors:
            return render_template(
                "register.html", errors=errors,
                username=username, email=email, gender=gender,
                registered_coins=REGISTERED_INITIAL_COINS,
            )

        user                          = User(username=username, password_hash=generate_password_hash(password))
        user.email                    = email
        user.gender                   = gender
        user.coins                    = REGISTERED_INITIAL_COINS
        user.kdf_salt                 = kdf_salt
        user.encrypted_dek            = encrypted_dek
        user.recovery_encrypted_dek   = recovery_encrypted_dek
        db.add(user)
        db.flush()

        log_transaction(db, user, +REGISTERED_INITIAL_COINS, "registration_bonus")
        db.commit()
        db.refresh(user)

        session["user_id"] = str(user.id)
        resp = make_response(redirect(url_for("index")))
        resp.delete_cookie(GUEST_COOKIE)
        return resp

    return render_template("register.html", errors=[],
                           registered_coins=REGISTERED_INITIAL_COINS)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        db       = g.db
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = db.query(User).filter(User.username == username).first()
        if not user or not check_password_hash(user.password_hash, password):
            return render_template("login.html",
                                   error="Invalid username or password.",
                                   username=username)

        session["user_id"] = str(user.id)
        resp = make_response(redirect(url_for("index")))
        resp.delete_cookie(GUEST_COOKIE)
        return resp

    return render_template("login.html", error=None)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# -----------------------------------
# E2EE: key bootstrap endpoints
# -----------------------------------

@app.route("/api/kdf-params", methods=["POST"])
def kdf_params():
    """
    Called by the login page BEFORE password is submitted,
    so JS can derive the key client-side.
    Also used during recovery flow.
    """
    data     = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    db       = g.db
    user     = db.query(User).filter(User.username == username).first()
    if not user:
        # Return fake data to prevent username enumeration
        return jsonify({"salt": "0" * 32, "encrypted_dek": "", "recovery_encrypted_dek": ""})
    return jsonify({
        "salt":                   user.kdf_salt,
        "encrypted_dek":          user.encrypted_dek,
        "recovery_encrypted_dek": user.recovery_encrypted_dek,
    })


@app.route("/api/save-message", methods=["POST"])
def save_message():
    """Store a browser-encrypted message (ciphertext only — server is blind)."""
    db   = g.db
    user = get_current_user(db)
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    data         = request.get_json(silent=True) or {}
    role         = data.get("role", "")
    content_enc  = data.get("content_enc", "")   # hex ciphertext from browser

    if role not in ("user", "agent") or not content_enc:
        return jsonify({"error": "Invalid payload"}), 400

    msg             = ChatMessage(user_id=user.id, role=role)
    msg.content_enc = content_enc          # stored as-is, server cannot read it
    db.add(msg)
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/messages")
def get_messages():
    """Return encrypted message blobs — client decrypts them."""
    db   = g.db
    user = get_current_user(db)
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    msgs = (
        db.query(ChatMessage)
        .filter(ChatMessage.user_id == user.id)
        .order_by(ChatMessage.created_at)
        .all()
    )
    return jsonify([
        {"role": m.role, "content_enc": m.content_enc, "created_at": m.created_at.isoformat()}
        for m in msgs
    ])


# -----------------------------------
# Routes: delete account
# -----------------------------------

@app.route("/delete-account", methods=["POST"])
def delete_account():
    db   = g.db
    user = get_current_user(db)
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    try:
        db.query(CoinTransaction).filter(CoinTransaction.user_id == user.id).delete(synchronize_session=False)
        db.query(ChatMessage).filter(ChatMessage.user_id == user.id).delete(synchronize_session=False)
        db.delete(user)
        db.commit()
    except Exception as e:
        db.rollback()
        print("ERROR deleting account:", repr(e))
        return jsonify({"error": f"Could not delete account: {e}"}), 500

    session.clear()
    resp = make_response(jsonify({"ok": True}))
    resp.delete_cookie(GUEST_COOKIE)
    return resp


# -----------------------------------
# Routes: main
# -----------------------------------

@app.route("/")
def index():
    db   = g.db
    user = get_current_user(db)

    if user:
        return render_template("index.html",
                               username=user.username,
                               coins=user.coins,
                               is_guest=False,
                               paystack_public_key=PAYSTACK_PUBLIC_KEY)

    guest_id = request.args.get("guest_id", "")
    if not guest_id:
        return render_template("index.html",
                               username="Guest",
                               coins=GUEST_INITIAL_COINS,
                               is_guest=True,
                               paystack_public_key=PAYSTACK_PUBLIC_KEY,
                               guest_id="")

    coins = get_guest_coins_redis(guest_id)
    return render_template("index.html",
                           username="Guest",
                           coins=coins,
                           is_guest=True,
                           paystack_public_key=PAYSTACK_PUBLIC_KEY,
                           guest_id=guest_id)


@app.route("/chat", methods=["POST"])
def chat():
    db       = g.db
    user     = get_current_user(db)
    is_guest = user is None

    data     = request.get_json(silent=True) or {}
    guest_id = None

    if is_guest:
        guest_id = data.get("guest_id", "")
        coins    = get_guest_coins_redis(guest_id) if guest_id else 0
        if coins <= 0:
            return jsonify({"error": "no_coins"}), 403
    else:
        if user.coins <= 0:
            return jsonify({"error": "no_coins"}), 403

    # For logged-in users the browser sends the ENCRYPTED user message
    # and we forward the PLAINTEXT to Mistral (we have to — the AI needs to read it).
    # What we store server-side afterwards is only the re-encrypted ciphertext via /api/save-message.
    user_message = data.get("message", "")
    if not user_message:
        return jsonify({"error": "No message provided"}), 400
    if not MISTRAL_API_KEY:
        return jsonify({"error": "MISTRAL_API_KEY not set"}), 500

    try:
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
            set_guest_coins_redis(guest_id, current_coins)
        else:
            current_coins = max(0, user.coins - cost)
            user.coins    = current_coins
            log_transaction(db, user, -cost, f"chat_message tokens={total_tokens}")
            db.commit()
            db.refresh(user)

        return jsonify({
            "reply":    reply,
            "usage":    {
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
# Routes: Paystack
# -----------------------------------

@app.route("/payment/init", methods=["POST"])
def payment_init():
    db   = g.db
    user = get_current_user(db)
    if not user:
        return jsonify({"error": "Login required to make payments"}), 401

    data    = request.get_json(silent=True) or {}
    pack_id = (data.get("pack") or "").strip()
    pack    = COIN_PACKS.get(pack_id)
    if not pack:
        return jsonify({"error": "Invalid pack"}), 400
    if not PAYSTACK_SECRET_KEY:
        return jsonify({"error": "PAYSTACK_SECRET_KEY not configured"}), 500

    reference = f"coins_{user.id}_{uuid.uuid4().hex[:12]}"
    payload   = {
        "email":        user.email,
        "amount":       pack["price_kes"] * 100,
        "currency":     "KES",
        "reference":    reference,
        "callback_url": url_for("payment_callback", _external=True),
        "metadata":     {"pack_id": pack_id, "user_id": str(user.id)},
    }

    try:
        r = http_requests.post("https://api.paystack.co/transaction/initialize",
                               json=payload, headers=PAYSTACK_HEADERS(), timeout=10)
        resp_data = r.json()
    except Exception as e:
        return jsonify({"error": f"Could not reach Paystack: {e}"}), 502

    if not resp_data.get("status"):
        return jsonify({"error": resp_data.get("message", "Unknown Paystack error")}), 502

    return jsonify({"authorization_url": resp_data["data"]["authorization_url"], "reference": reference})


@app.route("/payment/callback")
def payment_callback():
    reference = request.args.get("reference", "")
    if not reference:
        return redirect(url_for("index"))
    try:
        r         = http_requests.get(f"https://api.paystack.co/transaction/verify/{reference}",
                                      headers=PAYSTACK_HEADERS(), timeout=10)
        resp_data = r.json()
    except Exception:
        return redirect(url_for("index") + "?payment=failed")

    if not resp_data.get("status") or resp_data["data"].get("status") != "success":
        return redirect(url_for("index") + "?payment=failed")

    meta    = resp_data["data"].get("metadata", {})
    pack_id = meta.get("pack_id")
    user_id = meta.get("user_id")
    pack    = COIN_PACKS.get(pack_id)

    if pack and user_id:
        db   = g.db
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            user.coins += pack["coins"]
            log_transaction(db, user, +pack["coins"],
                            f"paystack_purchase pack={pack_id} ref={reference} kes={pack['price_kes']}")
            db.commit()

    return redirect(url_for("index") + "?payment=success")


@app.route("/payment/webhook", methods=["POST"])
def payment_webhook():
    sig      = request.headers.get("X-Paystack-Signature", "")
    body     = request.get_data()
    expected = hmac.new(PAYSTACK_SECRET_KEY.encode(), body, hashlib.sha512).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return "", 400

    event = request.get_json(silent=True) or {}
    if event.get("event") != "charge.success":
        return "", 200

    tx      = event.get("data", {})
    meta    = tx.get("metadata", {})
    pack_id = meta.get("pack_id")
    user_id = meta.get("user_id")
    pack    = COIN_PACKS.get(pack_id)

    if pack and user_id:
        db   = g.db
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            user.coins += pack["coins"]
            log_transaction(db, user, +pack["coins"],
                            f"paystack_webhook pack={pack_id} ref={tx.get('reference','webhook')} kes={pack['price_kes']}")
            db.commit()

    return "", 200


@app.route("/buy-coins", methods=["POST"])
def buy_coins():
    db   = g.db
    user = get_current_user(db)
    if not user:
        return jsonify({"error": "Login required"}), 401

    data   = request.get_json(silent=True) or {}
    amount = data.get("amount")
    try:
        amount = int(amount)
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid amount"}), 400

    if amount <= 0:     return jsonify({"error": "Amount must be positive"}), 400
    if amount > 1000000: return jsonify({"error": "Amount too large"}), 400

    user.coins += amount
    log_transaction(db, user, +amount, "manual_test_topup")
    db.commit()
    db.refresh(user)
    return jsonify({"coins": user.coins})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
