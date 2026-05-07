import logging
import os
import re
import socket
import sys
import uuid
import hmac
import hashlib
import json
import time
from datetime import datetime, timedelta, timezone

import redis
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, g
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from openai import OpenAI
from sqlalchemy.orm import Session
from sqlalchemy import desc

from database import get_engine, get_session_factory, init_db
from models import User, ChatMessage, CoinTransaction
from crypto import (
    generate_salt,
    derive_kek,
    generate_dek,
    encrypt_dek_with_kek,
    encrypt_data,
    decrypt_data,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Environment / config
# ---------------------------------------------------------------------------
CORTECS_API_KEY   = os.environ.get("CORTECS_API_KEY", "")
CORTECS_BASE_URL  = os.environ.get("CORTECS_BASE_URL", "https://api.cortecs.ai/v1")
CORTECS_MODEL     = os.environ.get("CORTECS_MODEL", "qwen3.5-9b")

SECRET_KEY        = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")
MAIL_SERVER       = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
MAIL_PORT         = int(os.environ.get("MAIL_PORT", 587))
MAIL_USE_TLS      = os.environ.get("MAIL_USE_TLS", "true").lower() == "true"
MAIL_USERNAME     = os.environ.get("MAIL_USERNAME", "")
MAIL_PASSWORD     = os.environ.get("MAIL_PASSWORD", "")
MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER", MAIL_USERNAME)

PAYSTACK_SECRET_KEY = os.environ.get("PAYSTACK_SECRET_KEY", "")
PAYSTACK_PUBLIC_KEY = os.environ.get("PAYSTACK_PUBLIC_KEY", "")
APP_BASE_URL        = os.environ.get("APP_BASE_URL", "http://localhost:5000")

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

GUEST_COIN_ALLOWANCE = int(os.environ.get("GUEST_COIN_ALLOWANCE", 500))
GUEST_COIN_TTL       = int(os.environ.get("GUEST_COIN_TTL", 86400))  # seconds

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------
# Rules are flat and numbered — Qwen3.5 small models follow
# numbered lists reliably when think=false is in effect.
# (supported by the Qwen3 model family).
SYSTEM_PROMPT = os.environ.get("SYSTEM_PROMPT", """You are a helpful assistant.""")

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = SECRET_KEY

# Mail
app.config["MAIL_SERVER"]         = MAIL_SERVER
app.config["MAIL_PORT"]           = MAIL_PORT
app.config["MAIL_USE_TLS"]        = MAIL_USE_TLS
app.config["MAIL_USERNAME"]       = MAIL_USERNAME
app.config["MAIL_PASSWORD"]       = MAIL_PASSWORD
app.config["MAIL_DEFAULT_SENDER"] = MAIL_DEFAULT_SENDER
mail = Mail(app)

serializer = URLSafeTimedSerializer(SECRET_KEY)

# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------
engine          = get_engine()
SessionFactory  = get_session_factory(engine)
init_db(engine)

@app.before_request
def open_db():
    g.db = SessionFactory()

@app.teardown_request
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

# ---------------------------------------------------------------------------
# Redis helpers
# ---------------------------------------------------------------------------
def get_redis():
    return redis.from_url(REDIS_URL, decode_responses=True)

def guest_coins_key(guest_id: str) -> str:
    return f"guest_coins:{guest_id}"

def get_guest_coins_redis(guest_id: str) -> int:
    try:
        r = get_redis()
        val = r.get(guest_coins_key(guest_id))
        if val is None:
            r.setex(guest_coins_key(guest_id), GUEST_COIN_TTL, GUEST_COIN_ALLOWANCE)
            return GUEST_COIN_ALLOWANCE
        return int(val)
    except Exception as e:
        log.warning("Redis get error: %s", repr(e))
        return GUEST_COIN_ALLOWANCE

def set_guest_coins_redis(guest_id: str, coins: int):
    r = get_redis()
    r.setex(guest_coins_key(guest_id), GUEST_COIN_TTL, coins)

# ---------------------------------------------------------------------------
# Cortecs client
# ---------------------------------------------------------------------------
def get_cortex_client():
    if not CORTECS_API_KEY:
        raise RuntimeError("CORTECS_API_KEY environment variable is not set.")
    return OpenAI(api_key=CORTECS_API_KEY, base_url=CORTECS_BASE_URL)

# ---------------------------------------------------------------------------
# Reply extraction helpers
# ---------------------------------------------------------------------------
def _clean(text):
    """
    Strip <think>...</think> blocks (Qwen3 /no_think output).
    Also handles unclosed tags: <think>...EOF.
    """
    if not text:
        return ""
    # Remove complete <think>...</think> blocks (non-greedy, DOTALL)
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    # Remove any remaining open <think> block to end of string
    text = re.sub(r"<think>.*", "", text, flags=re.DOTALL)
    return text.strip()


def extract_reply(choice):
    """
    Extract the assistant text from a chat completion Choice.

    Qwen3 models with /no_think may return:
      - message.content  as None / empty string when the model emits
        only a <think> block and nothing else.
      - message.reasoning_content  with the actual answer text
        (Cortecs-specific extension field).

    Strategy:
      1. message.content  — strip <think> blocks, use if non-empty
      2. message.reasoning_content  — same stripping
      3. Empty string (caller handles "empty response" notice)
    """
    msg = choice.message

    # 1. Try content first (normal path)
    content = _clean(getattr(msg, "content", None) or "")
    if content:
        return content

    # 2. Try reasoning_content (Cortecs-specific fallback)
    reasoning = _clean(getattr(msg, "reasoning_content", None) or "")
    if reasoning:
        return reasoning

    return ""


# ---------------------------------------------------------------------------
# Transaction logger
# ---------------------------------------------------------------------------
def log_transaction(db, user, delta, note=""):
    tx = CoinTransaction(
        user_id=user.id,
        delta=delta,
        note=note,
        created_at=datetime.now(timezone.utc),
    )
    db.add(tx)


# ---------------------------------------------------------------------------
# Coin packs
# ---------------------------------------------------------------------------
COIN_PACKS = {
    "small":   {"coins": 5_000,  "amount_kes": 70,  "label": "5,000 coins — KES 70"},
    "regular": {"coins": 30_000, "amount_kes": 300, "label": "30,000 coins — KES 300"},
    "heavy":   {"coins": 80_000, "amount_kes": 700, "label": "80,000 coins — KES 700"},
}

# ---------------------------------------------------------------------------
# Routes: auth
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    db = g.db

    # ── Guest path ──────────────────────────────────────────────────────────
    guest_id = request.args.get("guest_id") or request.cookies.get("guest_id")
    if "user_id" not in session:
        if not guest_id:
            # First visit — redirect with a fresh guest_id so JS can read it
            guest_id = str(uuid.uuid4())
            resp = redirect(url_for("index", guest_id=guest_id))
            resp.set_cookie("guest_id", guest_id, max_age=GUEST_COIN_TTL)
            return resp

        coins = get_guest_coins_redis(guest_id)
        return render_template(
            "index.html",
            is_guest=True,
            username="Guest",
            coins=coins,
            guest_id=guest_id,
        )

    # ── Logged-in path ───────────────────────────────────────────────────────
    user = db.query(User).filter_by(id=session["user_id"]).first()
    if not user:
        session.clear()
        return redirect(url_for("login"))

    return render_template(
        "index.html",
        is_guest=False,
        username=user.username,
        coins=user.coins,
        guest_id=None,
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    db = g.db
    if request.method == "GET":
        return render_template("register.html")

    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email    = (data.get("email")    or "").strip().lower()
    password =  data.get("password") or ""

    if not username or not email or not password:
        return jsonify({"error": "All fields are required."}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters."}), 400

    if db.query(User).filter_by(username=username).first():
        return jsonify({"error": "Username already taken."}), 409
    if db.query(User).filter_by(email=email).first():
        return jsonify({"error": "Email already registered."}), 409

    # Derive KEK from password, generate + encrypt DEK
    salt_hex        = generate_salt()
    kek             = derive_kek(password, salt_hex)
    dek_bytes       = generate_dek()
    encrypted_dek   = encrypt_dek_with_kek(dek_bytes, kek)  # "iv_hex:ct_hex"

    user = User(
        username=username,
        email=email,
        coins=15_000,
        email_verified=False,
        kdf_salt=salt_hex,
        encrypted_dek=encrypted_dek,
    )
    user.set_password(password)
    db.add(user)
    db.commit()
    db.refresh(user)

    # Send verification email
    try:
        token = serializer.dumps(email, salt="email-verify")
        verify_url = url_for("verify_email", token=token, _external=True)
        msg = Message(
            subject="Verify your email",
            recipients=[email],
            body=f"Click to verify: {verify_url}\n\nThis link expires in 1 hour.",
        )
        mail.send(msg)
    except Exception as e:
        log.warning("Email send failed: %s", repr(e))

    return jsonify({"ok": True, "message": "Registered! Check your email to verify."}), 201


@app.route("/verify-email")
def verify_email():
    token = request.args.get("token", "")
    try:
        email = serializer.loads(token, salt="email-verify", max_age=3600)
    except (SignatureExpired, BadSignature):
        return render_template("verify_email.html", success=False,
                               message="Verification link is invalid or expired.")

    db = g.db
    user = db.query(User).filter_by(email=email).first()
    if not user:
        return render_template("verify_email.html", success=False,
                               message="User not found.")

    user.email_verified = True
    db.commit()
    return render_template("verify_email.html", success=True,
                           message="Email verified! You can now log in.")


@app.route("/login", methods=["GET", "POST"])
def login():
    db = g.db
    if request.method == "GET":
        return render_template("login.html")

    data     = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password =  data.get("password") or ""

    user = db.query(User).filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({"error": "Invalid credentials."}), 401

    session["user_id"] = user.id
    return jsonify({"ok": True})


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/delete-account", methods=["POST"])
def delete_account():
    db = g.db
    if "user_id" not in session:
        return jsonify({"error": "Not logged in."}), 401

    user = db.query(User).filter_by(id=session["user_id"]).first()
    if not user:
        session.clear()
        return jsonify({"error": "User not found."}), 404

    db.delete(user)
    db.commit()
    session.clear()
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Routes: recover password
# ---------------------------------------------------------------------------
@app.route("/recover", methods=["GET", "POST"])
def recover():
    db = g.db
    if request.method == "GET":
        return render_template("recover.html")

    data  = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return jsonify({"error": "Email is required."}), 400

    user = db.query(User).filter_by(email=email).first()
    if user:
        try:
            token      = serializer.dumps(email, salt="password-reset")
            reset_url  = url_for("reset_password", token=token, _external=True)
            msg = Message(
                subject="Reset your password",
                recipients=[email],
                body=f"Click to reset: {reset_url}\n\nThis link expires in 1 hour.",
            )
            mail.send(msg)
        except Exception as e:
            log.warning("Reset email failed: %s", repr(e))

    return jsonify({"ok": True, "message": "If that email exists, a reset link was sent."})


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    db = g.db
    token = request.args.get("token", "")

    if request.method == "GET":
        try:
            serializer.loads(token, salt="password-reset", max_age=3600)
            return render_template("recover.html", reset_mode=True, token=token)
        except (SignatureExpired, BadSignature):
            return render_template("recover.html", reset_mode=True, token=None,
                                   error="Link invalid or expired.")

    data        = request.get_json(silent=True) or {}
    new_password = data.get("password") or ""
    if len(new_password) < 6:
        return jsonify({"error": "Password must be at least 6 characters."}), 400

    try:
        email = serializer.loads(token, salt="password-reset", max_age=3600)
    except (SignatureExpired, BadSignature):
        return jsonify({"error": "Link invalid or expired."}), 400

    user = db.query(User).filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User not found."}), 404

    # Re-derive KEK with new password, re-encrypt DEK
    new_salt        = generate_salt()
    new_kek         = derive_kek(new_password, new_salt)

    # We need to decrypt the old DEK to re-encrypt it.
    # If the admin is doing this (knows old password) that's the normal case.
    # For a "forgot password" reset the DEK is lost — we generate a fresh one
    # (existing history becomes unreadable but the account stays functional).
    try:
        # Try to preserve DEK if possible (requires old KDF params to still work)
        raise ValueError("fresh reset — generate new DEK")
    except Exception:
        dek_bytes = generate_dek()

    new_encrypted_dek = encrypt_dek_with_kek(dek_bytes, new_kek)

    user.set_password(new_password)
    user.kdf_salt     = new_salt
    user.encrypted_dek = new_encrypted_dek
    db.commit()
    return jsonify({"ok": True, "message": "Password reset. Please log in."})


# ---------------------------------------------------------------------------
# Routes: encrypted chat history
# ---------------------------------------------------------------------------
@app.route("/api/kdf-params", methods=["POST"])
def kdf_params():
    db = g.db
    data     = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()

    user = db.query(User).filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found."}), 404

    return jsonify({
        "salt":          user.kdf_salt,
        "encrypted_dek": user.encrypted_dek,
    })


@app.route("/api/save-message", methods=["POST"])
def save_message():
    db = g.db
    if "user_id" not in session:
        return jsonify({"error": "Not logged in."}), 401

    data    = request.get_json(silent=True) or {}
    role    = data.get("role")    or ""
    content = data.get("content") or ""
    sid     = data.get("chat_session_id") or ""

    if role not in ("user", "agent"):
        return jsonify({"error": "Invalid role."}), 400
    if not content:
        return jsonify({"error": "Empty content."}), 400

    msg = ChatMessage(
        user_id=session["user_id"],
        role=role,
        content=content,
        chat_session_id=sid or None,
        created_at=datetime.now(timezone.utc),
    )
    db.add(msg)
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/messages", methods=["GET"])
def get_messages():
    db = g.db
    if "user_id" not in session:
        return jsonify({"error": "Not logged in."}), 401

    msgs = (
        db.query(ChatMessage)
        .filter_by(user_id=session["user_id"])
        .order_by(ChatMessage.created_at)
        .all()
    )
    return jsonify([
        {
            "id":              m.id,
            "role":            m.role,
            "content":         m.content,
            "chat_session_id": m.chat_session_id,
            "created_at":      m.created_at.isoformat() if m.created_at else None,
        }
        for m in msgs
    ])


@app.route("/api/delete-session", methods=["POST"])
def delete_session_route():
    db = g.db
    if "user_id" not in session:
        return jsonify({"error": "Not logged in."}), 401

    data = request.get_json(silent=True) or {}
    sid  = data.get("chat_session_id") or ""
    if not sid:
        return jsonify({"error": "chat_session_id required."}), 400

    db.query(ChatMessage).filter_by(
        user_id=session["user_id"],
        chat_session_id=sid,
    ).delete()
    db.commit()
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Routes: coins
# ---------------------------------------------------------------------------
@app.route("/buy-coins", methods=["POST"])
def buy_coins():
    db = g.db
    if "user_id" not in session:
        return jsonify({"error": "Not logged in."}), 401

    data   = request.get_json(silent=True) or {}
    amount = int(data.get("amount", 0))
    if amount <= 0:
        return jsonify({"error": "Invalid amount."}), 400

    user = db.query(User).filter_by(id=session["user_id"]).first()
    if not user:
        return jsonify({"error": "User not found."}), 404

    user.coins += amount
    log_transaction(db, user, amount, "manual top-up (test)")
    db.commit()
    db.refresh(user)
    return jsonify({"coins": user.coins})


# ---------------------------------------------------------------------------
# Routes: chat
# ---------------------------------------------------------------------------
@app.route("/chat", methods=["POST"])
def chat():
    db = g.db
    data         = request.get_json(silent=True) or {}
    user_message = (data.get("message") or "").strip()

    if not user_message:
        return jsonify({"error": "Empty message."}), 400

    # ── Auth / coins ─────────────────────────────────────────────────────────
    is_guest = "user_id" not in session
    user     = None
    coins    = 0
    guest_id = None

    if is_guest:
        guest_id = (data.get("guest_id") or "").strip()
        if not guest_id:
            return jsonify({"error": "guest_id required for guest chat."}), 400
        coins = get_guest_coins_redis(guest_id)
    else:
        user = db.query(User).filter_by(id=session["user_id"]).first()
        if not user:
            return jsonify({"error": "User not found."}), 404
        coins = user.coins

    if coins <= 0:
        return jsonify({"error": "no_coins"}), 403

    if not CORTECS_API_KEY:
        return jsonify({"error": "CORTECS_API_KEY not set"}), 500

    # Build message list:
    # 1. System prompt (always first — Qwen3.5 follows system role reliably)
    # 2. Conversation history from client (optional, for multi-turn)
    # 3. Latest user message
    history = data.get("history", [])
    messages = (
        [{"role": "system", "content": SYSTEM_PROMPT}]
        + list(history)
        + [{"role": "user", "content": user_message}]
    )

    try:
        client = get_cortex_client()

        # --- dynamic model / extra_body / reasoning_effort from client ---
        req_model = data.get("model") or CORTECS_MODEL
        req_extra_body = data.get("extra_body", {"chat_template_kwargs": {"enable_thinking": False}})
        req_reasoning_effort = data.get("reasoning_effort")  # "low" | "medium" | "high" | None

        # Merge reasoning_effort into extra_body if supplied
        if req_reasoning_effort:
            req_extra_body = dict(req_extra_body) if isinstance(req_extra_body, dict) else {}
            req_extra_body["reasoning_effort"] = req_reasoning_effort

        create_kwargs = dict(
            model=req_model,
            messages=messages,
            max_tokens=1024,
            stream=False,
        )
        if req_extra_body:
            create_kwargs["extra_body"] = req_extra_body

        response = client.chat.completions.create(**create_kwargs)

        reply = ""
        if response.choices:
            reply = extract_reply(response.choices[0])

        usage = response.usage
        prompt_tokens = getattr(usage, "prompt_tokens", None) if usage else None
        completion_tokens = getattr(usage, "completion_tokens", None) if usage else None
        total_tokens = getattr(usage, "total_tokens", None) if usage else None

        if not reply:
            reply = "Model returned an empty response."

        cost = total_tokens if isinstance(total_tokens, int) and total_tokens > 0 else 1

        if is_guest:
            current_coins = max(0, coins - cost)
            try:
                set_guest_coins_redis(guest_id, current_coins)
            except Exception as e:
                print("Redis set error for guest:", repr(e))
        else:
            current_coins = max(0, user.coins - cost)
            user.coins = current_coins
            log_transaction(
                db,
                user,
                -cost,
                f"chat tokens={total_tokens} prompt={prompt_tokens} completion={completion_tokens}",
            )
            db.commit()
            db.refresh(user)

        return jsonify({
            "reply": reply,
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": total_tokens,
            },
            "coins": current_coins,
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
    db = g.db
    if "user_id" not in session:
        return jsonify({"error": "Not logged in."}), 401

    user = db.query(User).filter_by(id=session["user_id"]).first()
    if not user:
        return jsonify({"error": "User not found."}), 404

    data   = request.get_json(silent=True) or {}
    pack_id = data.get("pack")
    pack   = COIN_PACKS.get(pack_id)
    if not pack:
        return jsonify({"error": "Invalid pack."}), 400

    if not PAYSTACK_SECRET_KEY:
        return jsonify({"error": "Paystack not configured."}), 500

    import urllib.request as urlreq
    amount_kobo = pack["amount_kes"] * 100   # Paystack uses kobo (1/100 KES)
    ref         = f"pay_{uuid.uuid4().hex}"

    payload = json.dumps({
        "email":     user.email,
        "amount":    amount_kobo,
        "currency":  "KES",
        "reference": ref,
        "callback_url": f"{APP_BASE_URL}/payment/verify?ref={ref}&pack={pack_id}",
        "metadata": {"pack": pack_id, "user_id": user.id},
    }).encode()

    req = urlreq.Request(
        "https://api.paystack.co/transaction/initialize",
        data=payload,
        headers={
            "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
            "Content-Type":  "application/json",
        },
        method="POST",
    )
    try:
        with urlreq.urlopen(req) as resp:
            result = json.load(resp)
    except Exception as e:
        return jsonify({"error": f"Paystack error: {e}"}), 500

    if not result.get("status"):
        return jsonify({"error": result.get("message", "Paystack error")}), 500

    return jsonify({"authorization_url": result["data"]["authorization_url"]})


@app.route("/payment/verify")
def payment_verify():
    db   = g.db
    ref  = request.args.get("ref", "")
    pack_id = request.args.get("pack", "")

    pack = COIN_PACKS.get(pack_id)
    if not pack or not ref:
        return redirect(url_for("index", payment="failed"))

    import urllib.request as urlreq
    req = urlreq.Request(
        f"https://api.paystack.co/transaction/verify/{ref}",
        headers={"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"},
    )
    try:
        with urlreq.urlopen(req) as resp:
            result = json.load(resp)
    except Exception:
        return redirect(url_for("index", payment="failed"))

    if not result.get("status") or result["data"].get("status") != "success":
        return redirect(url_for("index", payment="failed"))

    meta    = result["data"].get("metadata", {})
    user_id = meta.get("user_id")
    if not user_id:
        return redirect(url_for("index", payment="failed"))

    user = db.query(User).filter_by(id=user_id).first()
    if not user:
        return redirect(url_for("index", payment="failed"))

    user.coins += pack["coins"]
    log_transaction(db, user, pack["coins"], f"Paystack {pack_id} ref={ref}")
    db.commit()
    return redirect(url_for("index", payment="success"))


@app.route("/payment/webhook", methods=["POST"])
def payment_webhook():
    db = g.db

    sig   = request.headers.get("x-paystack-signature", "")
    body  = request.get_data()
    expected = hmac.new(PAYSTACK_SECRET_KEY.encode(), body, hashlib.sha512).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return "", 400

    event = request.get_json(silent=True) or {}
    if event.get("event") != "charge.success":
        return "", 200

    data    = event.get("data", {})
    meta    = data.get("metadata", {})
    pack_id = meta.get("pack")
    user_id = meta.get("user_id")
    pack    = COIN_PACKS.get(pack_id)

    if not pack or not user_id:
        return "", 200

    user = db.query(User).filter_by(id=user_id).first()
    if not user:
        return "", 200

    user.coins += pack["coins"]
    log_transaction(db, user, pack["coins"], f"webhook Paystack {pack_id}")
    db.commit()
    return "", 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
