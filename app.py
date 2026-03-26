import logging
import os
import socket
import uuid
import hmac
import hashlib
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

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

from database import SessionLocal, run_migrations
from models import User, ChatMessage, CoinTransaction


# -----------------------------------
# Flask setup
# -----------------------------------
app = Flask(__name__, template_folder="templates")
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-change-me")

MISTRAL_API_KEY = os.environ.get("MISTRAL_API_KEY", "")
AGENT_ID = "ag_019cf8b9404e73c7ad980dfc212fbd26"

PAYSTACK_SECRET_KEY = os.environ.get("PAYSTACK_SECRET_KEY", "")
PAYSTACK_PUBLIC_KEY = os.environ.get("PAYSTACK_PUBLIC_KEY", "")

GUEST_INITIAL_COINS = 5000
REGISTERED_INITIAL_COINS = 15000

GUEST_COOKIE = "guest_token"
GUEST_TTL = 60 * 60 * 24 * 30  # 30 days

COIN_PACKS = {
    "small": {"coins": 5000, "price_kes": 70, "label": "Small pack"},
    "regular": {"coins": 30000, "price_kes": 300, "label": "Regular pack"},
    "heavy": {"coins": 80000, "price_kes": 700, "label": "Heavy-use pack"},
}

PAYSTACK_HEADERS = lambda: {
    "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
    "Content-Type": "application/json",
}

# -----------------------------------
# Mail settings (Railway env vars)
# -----------------------------------
MAIL_SERVER = os.environ.get("MAIL_SERVER", "")
MAIL_PORT = int(os.environ.get("MAIL_PORT", "587"))
MAIL_USERNAME = os.environ.get("MAIL_USERNAME", "")
MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD", "")
MAIL_FROM = os.environ.get("MAIL_FROM", "")
APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://localhost:5000").rstrip("/")

# -----------------------------------
# Mail configuration startup warnings
# -----------------------------------
logger = logging.getLogger(__name__)

if not MAIL_SERVER or not MAIL_FROM:
    logger.warning(
        "MAIL_SERVER or MAIL_FROM not set — email sending is disabled. "
        "Set MAIL_SERVER, MAIL_PORT, MAIL_USERNAME, MAIL_PASSWORD, and MAIL_FROM "
        "to enable verification emails."
    )
elif not MAIL_USERNAME or not MAIL_PASSWORD:
    logger.warning(
        "MAIL_SERVER is set but MAIL_USERNAME or MAIL_PASSWORD is missing. "
        "SMTP authentication will fail and emails will not be sent."
    )

if APP_BASE_URL.startswith("http://localhost"):
    logger.warning(
        "APP_BASE_URL is '%s' — verification links will point to localhost "
        "and be unreachable for real users. Set APP_BASE_URL to your public URL.",
        APP_BASE_URL,
    )


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


def redis_guest_key(gid):
    return f"guest_coins:{gid}"


def get_guest_coins_redis(gid):
    r, key = get_redis(), redis_guest_key(gid)
    val = r.get(key)
    if val is None:
        r.setex(key, GUEST_TTL, GUEST_INITIAL_COINS)
        return GUEST_INITIAL_COINS
    r.expire(key, GUEST_TTL)
    return int(val)


def set_guest_coins_redis(gid, coins):
    get_redis().setex(redis_guest_key(gid), GUEST_TTL, max(0, coins))


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
    uid = session.get("user_id")
    if not uid:
        return None
    return db.query(User).filter(User.id == uid).first()


def generate_verification_token():
    """Return a cryptographically secure 64-char hex token."""
    return secrets.token_hex(32)


def _resolve_smtp_ipv4(host: str, port: int) -> str:
    """Resolve *host* to an IPv4 address.

    Railway does not support outbound IPv6.  When a mail-server hostname
    resolves to both A and AAAA records the OS may try IPv6 first, which
    fails with ``OSError [Errno 101] Network is unreachable``.

    Returns the first IPv4 address found, or the original *host* string
    unchanged if resolution fails (so the caller can still attempt to
    connect and surface the real error).
    """
    try:
        results = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        if results:
            ipv4_addr = results[0][4][0]
            logger.info(
                "Resolved SMTP host %s to IPv4 address %s", host, ipv4_addr,
            )
            return ipv4_addr
    except socket.gaierror as exc:
        logger.warning(
            "IPv4 DNS resolution failed for %s:%d — falling back to hostname: %r",
            host, port, exc,
        )
    return host


class _IPv4SMTP(smtplib.SMTP):
    """SMTP subclass that forces all connections through IPv4 (``AF_INET``).

    On Railway, outbound IPv6 is not supported.  Even when we resolve the
    mail-server hostname to an IPv4 address up-front, ``smtplib.SMTP`` may
    still call ``socket.getaddrinfo`` internally (e.g. during ``connect`` or
    ``ehlo``) and pick an AAAA record.  Overriding ``_get_socket`` ensures
    the underlying TCP socket is always ``AF_INET``, regardless of what the
    OS resolver returns.
    """

    def _get_socket(self, host, port, timeout):
        """Create and return an IPv4-only TCP socket."""
        addrs = socket.getaddrinfo(
            host, port, socket.AF_INET, socket.SOCK_STREAM,
        )
        if not addrs:
            raise OSError(
                f"No IPv4 address found for {host}:{port}"
            )
        af, socktype, proto, canonname, sa = addrs[0]
        logger.info(
            "SMTP socket connecting to %s:%d via IPv4 address %s",
            host, port, sa[0],
        )
        sock = socket.socket(af, socktype, proto)
        sock.settimeout(timeout)
        sock.connect(sa)
        return sock


class _IPv4SMTP_SSL(smtplib.SMTP_SSL):
    """SMTP_SSL subclass that forces all connections through IPv4."""

    def _get_socket(self, host, port, timeout):
        """Create an IPv4-only TCP socket and wrap it with TLS."""
        import ssl as _ssl

        addrs = socket.getaddrinfo(
            host, port, socket.AF_INET, socket.SOCK_STREAM,
        )
        if not addrs:
            raise OSError(
                f"No IPv4 address found for {host}:{port}"
            )
        af, socktype, proto, canonname, sa = addrs[0]
        logger.info(
            "SMTP_SSL socket connecting to %s:%d via IPv4 address %s",
            host, port, sa[0],
        )
        sock = socket.socket(af, socktype, proto)
        sock.settimeout(timeout)
        sock.connect(sa)
        context = self.context if self.context else _ssl.create_default_context()
        return context.wrap_socket(sock, server_hostname=host)


def send_verification_email(to_email: str, token: str) -> bool:
    """
    Send a verification email with a clickable link.
    Returns True on success, False on failure (logged via logger).
    """
    if not MAIL_SERVER or not MAIL_FROM:
        logger.warning("Mail not configured (MAIL_SERVER or MAIL_FROM empty) — skipping verification email.")
        return False

    if not MAIL_USERNAME or not MAIL_PASSWORD:
        logger.error(
            "MAIL_USERNAME or MAIL_PASSWORD not set — cannot authenticate with SMTP server. "
            "Email to %s will not be sent.", to_email,
        )
        return False

    verify_url = f"{APP_BASE_URL}/verify-email/{token}"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Verify your email address"
    msg["From"] = MAIL_FROM
    msg["To"] = to_email

    text_body = (
        f"Welcome! Please verify your email by visiting this link:\n\n"
        f"{verify_url}\n\n"
        f"If you did not create an account, you can ignore this email."
    )
    html_body = (
        f"<p>Welcome! Please verify your email by clicking the link below:</p>"
        f'<p><a href="{verify_url}">{verify_url}</a></p>'
        f"<p>If you did not create an account, you can ignore this email.</p>"
    )

    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    # Resolve to IPv4 to avoid IPv6 failures on Railway
    smtp_host = _resolve_smtp_ipv4(MAIL_SERVER, MAIL_PORT)

    try:
        if MAIL_PORT == 465:
            server = _IPv4SMTP_SSL(smtp_host, MAIL_PORT, timeout=10)
        else:
            server = _IPv4SMTP(smtp_host, MAIL_PORT, timeout=10)
            server.ehlo()
            server.starttls()
            server.ehlo()

        server.login(MAIL_USERNAME, MAIL_PASSWORD)
        server.sendmail(MAIL_FROM, to_email, msg.as_string())
        server.quit()
        logger.info("Verification email sent to %s via %s", to_email, smtp_host)
        return True
    except smtplib.SMTPAuthenticationError as e:
        logger.error(
            "SMTP authentication failed for %s (server=%s [%s], port=%d, user=%s): %r",
            to_email, MAIL_SERVER, smtp_host, MAIL_PORT, MAIL_USERNAME, e,
        )
        return False
    except smtplib.SMTPException as e:
        logger.error(
            "SMTP error sending verification email to %s (server=%s [%s], port=%d): %r",
            to_email, MAIL_SERVER, smtp_host, MAIL_PORT, e,
        )
        return False
    except Exception as e:
        logger.error(
            "Unexpected error sending verification email to %s (server=%s [%s]): %r",
            to_email, MAIL_SERVER, smtp_host, e, exc_info=True,
        )
        return False


def log_transaction(db, user, delta: int, reason: str):
    """
    Write one auditable row to coin_transactions.
    Encrypted with the SERVER master key — readable by business owner,
    NOT by the user's E2EE DEK.

    delta > 0 = credit, delta < 0 = debit.
    Caller must db.commit() after calling this.
    """
    tx = CoinTransaction(user_id=user.id)
    tx.delta = delta
    tx.reason = reason
    db.add(tx)


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

        kdf_salt = request.form.get("kdf_salt", "").strip()
        encrypted_dek = request.form.get("encrypted_dek", "").strip()
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
                "register.html",
                errors=errors,
                username=username,
                email=email,
                gender=gender,
                registered_coins=REGISTERED_INITIAL_COINS,
            )

        token = generate_verification_token()

        user = User(
            username=username,
            password_hash=generate_password_hash(password),
        )
        user.email = email
        user.gender = gender
        user.coins = REGISTERED_INITIAL_COINS
        user.kdf_salt = kdf_salt
        user.encrypted_dek = encrypted_dek
        user.recovery_encrypted_dek = recovery_encrypted_dek
        user.verification_token = token
        # is_verified defaults to False

        db.add(user)
        db.flush()

        log_transaction(db, user, +REGISTERED_INITIAL_COINS, "registration_bonus")
        db.commit()
        db.refresh(user)

        # Send verification email and give the user accurate feedback
        email_sent = send_verification_email(email, token)

        # Do NOT log the user in yet — they must verify their email first.
        # Redirect to login with a notice.
        if email_sent:
            return render_template(
                "login.html",
                error="Registration successful! Please check your email and "
                      "click the verification link before logging in.",
                username=username,
            )
        else:
            return render_template(
                "login.html",
                error="Registration successful, but we couldn't send the "
                      "verification email. Please try resending it below.",
                username=username,
                show_resend=True,
            )

    return render_template(
        "register.html",
        errors=[],
        registered_coins=REGISTERED_INITIAL_COINS,
    )


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

        if not user.is_verified:
            return render_template(
                "login.html",
                error="Please verify your email before logging in. "
                      "Check your inbox for a verification link.",
                username=username,
                show_resend=True,
            )

        session["user_id"] = str(user.id)
        resp = make_response(redirect(url_for("index")))
        resp.delete_cookie(GUEST_COOKIE)
        return resp

    return render_template("login.html", error=None)


@app.route("/logout")
def logout():
    session.clear()
    resp = make_response(redirect(url_for("login")))
    resp.delete_cookie(GUEST_COOKIE)
    return resp


# -----------------------------------
# Routes: email verification
# -----------------------------------
@app.route("/verify-email/<token>")
def verify_email(token):
    """Handle the verification link clicked from the user's inbox."""
    db = g.db

    if not token or len(token) != 64:
        return render_template("verify_email.html", success=False,
                               message="Invalid verification link.")

    user = db.query(User).filter(User.verification_token == token).first()
    if not user:
        return render_template("verify_email.html", success=False,
                               message="This verification link is invalid or has already been used.")

    user.is_verified = True
    user.verification_token = None  # clear token so it can't be reused
    db.commit()

    return render_template("verify_email.html", success=True,
                           message="Your email has been verified! You can now log in.")


@app.route("/resend-verification", methods=["POST"])
def resend_verification():
    """Resend the verification email for an unverified user."""
    db = g.db
    username = request.form.get("username", "").strip()

    if not username:
        return render_template("login.html", error="Username is required to resend.",
                               username=username)

    user = db.query(User).filter(User.username == username).first()
    if not user:
        # Don't reveal whether username exists
        return render_template("login.html",
                               error="If that account exists, a new verification email has been sent.",
                               username=username)

    if user.is_verified:
        return render_template("login.html",
                               error="This account is already verified. Please log in.",
                               username=username)

    # Rotate the token for safety
    new_token = generate_verification_token()
    user.verification_token = new_token
    db.commit()

    email_sent = send_verification_email(user.email, new_token)

    if email_sent:
        return render_template("login.html",
                               error="A new verification email has been sent. Please check your inbox.",
                               username=username)
    else:
        return render_template("login.html",
                               error="We couldn't send the verification email right now. "
                                     "Please try again later or contact support.",
                               username=username,
                               show_resend=True)


# -----------------------------------
# Routes: delete account / delete chat
# -----------------------------------
@app.route("/delete-account", methods=["POST"])
def delete_account():
    db = g.db
    user = get_current_user(db)
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    try:
        db.query(CoinTransaction).filter(
            CoinTransaction.user_id == user.id
        ).delete(synchronize_session=False)

        db.query(ChatMessage).filter(
            ChatMessage.user_id == user.id
        ).delete(synchronize_session=False)

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


@app.route("/api/delete-session", methods=["POST"])
def delete_session():
    """
    Delete one conversation identified by chat_session_id
    for the currently logged-in user.
    """
    db = g.db
    user = get_current_user(db)
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json(silent=True) or {}
    chat_session_id = (data.get("chat_session_id") or "").strip()

    if not chat_session_id:
        return jsonify({"error": "Missing chat_session_id"}), 400

    try:
        deleted = (
            db.query(ChatMessage)
            .filter(
                ChatMessage.user_id == user.id,
                ChatMessage.chat_session_id == chat_session_id,
            )
            .delete(synchronize_session=False)
        )
        db.commit()
        return jsonify({"ok": True, "deleted": deleted})
    except Exception as e:
        db.rollback()
        return jsonify({"error": f"Could not delete session: {e}"}), 500


# -----------------------------------
# E2EE key bootstrap
# -----------------------------------
@app.route("/api/kdf-params", methods=["POST"])
def kdf_params():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()

    db = g.db
    user = db.query(User).filter(User.username == username).first()

    if not user:
        return jsonify({
            "salt": "0" * 32,
            "encrypted_dek": "",
            "recovery_encrypted_dek": "",
        })

    return jsonify({
        "salt": user.kdf_salt,
        "encrypted_dek": user.encrypted_dek,
        "recovery_encrypted_dek": user.recovery_encrypted_dek,
    })


# -----------------------------------
# Chat message storage (E2EE)
# -----------------------------------
@app.route("/api/save-message", methods=["POST"])
def save_message():
    """
    Store a single browser-encrypted message.
    content_enc = hex string: iv:ciphertext — opaque to the server.
    chat_session_id groups messages into one conversation.
    """
    db = g.db
    user = get_current_user(db)
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    data = request.get_json(silent=True) or {}
    role = data.get("role", "")
    content_enc = data.get("content_enc", "")
    chat_session_id = (data.get("chat_session_id") or "").strip()

    if role not in ("user", "agent") or not content_enc:
        return jsonify({"error": "Invalid payload"}), 400

    msg = ChatMessage(
        user_id=user.id,
        role=role,
        content_enc=content_enc,
        chat_session_id=chat_session_id or None,
    )

    db.add(msg)
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/messages")
def get_messages():
    """
    Return all encrypted message blobs for the logged-in user,
    grouped by chat_session_id so the browser can show a history list.
    """
    db = g.db
    user = get_current_user(db)
    if not user:
        return jsonify({"error": "Not authenticated"}), 401

    msgs = (
        db.query(ChatMessage)
        .filter(ChatMessage.user_id == user.id)
        .order_by(ChatMessage.created_at)
        .all()
    )

    result = []
    for m in msgs:
        # content_enc may come back as memoryview / bytes from PostgreSQL
        # if the DB column is BYTEA. Coerce to str for JSON serialization.
        raw = m.content_enc
        if isinstance(raw, (memoryview, bytes, bytearray)):
            raw = bytes(raw).decode("utf-8", errors="replace")

        result.append({
            "role": m.role,
            "content_enc": raw,
            "chat_session_id": m.chat_session_id,
            "created_at": m.created_at.isoformat() if m.created_at else None,
        })
    return jsonify(result)


# -----------------------------------
# Routes: main
# -----------------------------------
@app.route("/")
def index():
    db = g.db
    user = get_current_user(db)

    if user:
        return render_template(
            "index.html",
            username=user.username,
            coins=user.coins,
            is_guest=False,
            paystack_public_key=PAYSTACK_PUBLIC_KEY,
        )

    guest_id = request.args.get("guest_id", "")
    if not guest_id:
        return render_template(
            "index.html",
            username="Guest",
            coins=GUEST_INITIAL_COINS,
            is_guest=True,
            paystack_public_key=PAYSTACK_PUBLIC_KEY,
            guest_id="",
        )

    coins = get_guest_coins_redis(guest_id)
    return render_template(
        "index.html",
        username="Guest",
        coins=coins,
        is_guest=True,
        paystack_public_key=PAYSTACK_PUBLIC_KEY,
        guest_id=guest_id,
    )


@app.route("/chat", methods=["POST"])
def chat():
    db = g.db
    user = get_current_user(db)
    is_guest = user is None

    data = request.get_json(silent=True) or {}

    if is_guest:
        guest_id = data.get("guest_id", "")
        if not guest_id:
            return jsonify({"error": "Missing guest_id"}), 400
        try:
            coins = get_guest_coins_redis(guest_id)
        except Exception as e:
            print("Redis error for guest:", repr(e))
            return jsonify({"error": "Could not check guest coins — please try again."}), 503
        if coins <= 0:
            return jsonify({"error": "no_coins"}), 403
    else:
        if user.coins <= 0:
            return jsonify({"error": "no_coins"}), 403

    user_message = data.get("message", "")
    if not user_message:
        return jsonify({"error": "No message provided"}), 400

    if not MISTRAL_API_KEY:
        return jsonify({"error": "MISTRAL_API_KEY not set"}), 500

    try:
        client = get_mistral_client()

        response = client.agents.complete(
            messages=[UserMessage(content=user_message)],
            agent_id=AGENT_ID,
            max_tokens=512,
        )

        reply = ""
        if getattr(response, "choices", None):
            msg = response.choices[0].message
            content = getattr(msg, "content", "")
            if isinstance(content, str):
                reply = content
            elif isinstance(content, list):
                reply = "".join(str(p) for p in content if p)

        usage = getattr(response, "usage", None)
        prompt_tokens = getattr(usage, "prompt_tokens", None) if usage else None
        completion_tokens = getattr(usage, "completion_tokens", None) if usage else None
        total_tokens = getattr(usage, "total_tokens", None) if usage else None

        if not reply:
            reply = "Agent returned an empty response."

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
    user = get_current_user(db)
    if not user:
        return jsonify({"error": "Login required to make payments"}), 401

    data = request.get_json(silent=True) or {}
    pack_id = (data.get("pack") or "").strip()
    pack = COIN_PACKS.get(pack_id)

    if not pack:
        return jsonify({"error": "Invalid pack"}), 400
    if not PAYSTACK_SECRET_KEY:
        return jsonify({"error": "PAYSTACK_SECRET_KEY not configured"}), 500

    reference = f"coins_{user.id}_{uuid.uuid4().hex[:12]}"
    payload = {
        "email": user.email,
        "amount": pack["price_kes"] * 100,
        "currency": "KES",
        "reference": reference,
        "callback_url": url_for("payment_callback", _external=True),
        "metadata": {"pack_id": pack_id, "user_id": str(user.id)},
    }

    try:
        r = http_requests.post(
            "https://api.paystack.co/transaction/initialize",
            json=payload,
            headers=PAYSTACK_HEADERS(),
            timeout=10,
        )
        resp_data = r.json()
    except Exception as e:
        return jsonify({"error": f"Could not reach Paystack: {e}"}), 502

    if not resp_data.get("status"):
        return jsonify({"error": resp_data.get("message", "Unknown Paystack error")}), 502

    return jsonify({
        "authorization_url": resp_data["data"]["authorization_url"],
        "reference": reference,
    })


@app.route("/payment/callback")
def payment_callback():
    reference = request.args.get("reference", "")
    if not reference:
        return redirect(url_for("index"))

    try:
        r = http_requests.get(
            f"https://api.paystack.co/transaction/verify/{reference}",
            headers=PAYSTACK_HEADERS(),
            timeout=10,
        )
        resp_data = r.json()
    except Exception:
        return redirect(url_for("index") + "?payment=failed")

    if not resp_data.get("status") or resp_data["data"].get("status") != "success":
        return redirect(url_for("index") + "?payment=failed")

    meta = resp_data["data"].get("metadata", {})
    pack_id = meta.get("pack_id")
    user_id = meta.get("user_id")
    pack = COIN_PACKS.get(pack_id)

    if pack and user_id:
        db = g.db
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            user.coins += pack["coins"]
            log_transaction(
                db,
                user,
                +pack["coins"],
                f"paystack_purchase pack={pack_id} ref={reference} kes={pack['price_kes']}",
            )
            db.commit()

    return redirect(url_for("index") + "?payment=success")


@app.route("/payment/webhook", methods=["POST"])
def payment_webhook():
    sig = request.headers.get("X-Paystack-Signature", "")
    body = request.get_data()
    expected = hmac.new(
        PAYSTACK_SECRET_KEY.encode(),
        body,
        hashlib.sha512,
    ).hexdigest()

    if not hmac.compare_digest(sig, expected):
        return "", 400

    event = request.get_json(silent=True) or {}
    if event.get("event") != "charge.success":
        return "", 200

    tx = event.get("data", {})
    meta = tx.get("metadata", {})
    pack_id = meta.get("pack_id")
    user_id = meta.get("user_id")
    pack = COIN_PACKS.get(pack_id)

    if pack and user_id:
        db = g.db
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            user.coins += pack["coins"]
            log_transaction(
                db,
                user,
                +pack["coins"],
                f"paystack_webhook pack={pack_id} ref={tx.get('reference', 'webhook')} kes={pack['price_kes']}",
            )
            db.commit()

    return "", 200


@app.route("/buy-coins", methods=["POST"])
def buy_coins():
    db = g.db
    user = get_current_user(db)
    if not user:
        return jsonify({"error": "Login required"}), 401

    data = request.get_json(silent=True) or {}
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
    log_transaction(db, user, +amount, "manual_test_topup")
    db.commit()
    db.refresh(user)

    return jsonify({"coins": user.coins})


# -----------------------------------
# Routes: recovery
# -----------------------------------
@app.route("/recover")
def recover():
    return render_template("recover.html")


@app.route("/api/reset-password", methods=["POST"])
def reset_password():
    db = g.db
    data = request.get_json(silent=True) or {}

    username = (data.get("username") or "").strip()
    new_password = data.get("new_password", "")
    kdf_salt = data.get("kdf_salt", "")
    encrypted_dek = data.get("encrypted_dek", "")

    if not all([username, new_password, kdf_salt, encrypted_dek]):
        return jsonify({"error": "Missing fields"}), 400

    user = db.query(User).filter(User.username == username).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    user.password_hash = generate_password_hash(new_password)
    user.kdf_salt = kdf_salt
    user.encrypted_dek = encrypted_dek
    db.commit()

    return jsonify({"ok": True})


if __name__ == "__main__":
    run_migrations()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
