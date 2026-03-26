"""
Tests for the email verification flow.

Runs against a SQLite in-memory database so no external Postgres is needed.
Patches SMTP so no real email is sent during tests.
"""

import os
import sys
import uuid
from unittest.mock import patch, MagicMock

import pytest

# ---------------------------------------------------------------------------
# Environment stubs – must be set BEFORE importing app / models / crypto
# ---------------------------------------------------------------------------
os.environ.setdefault("DATABASE_URL", "sqlite:///")  # overridden per-test below
os.environ.setdefault("FLASK_SECRET_KEY", "test-secret")
os.environ.setdefault("MISTRAL_API_KEY", "test")
os.environ.setdefault("PAYSTACK_SECRET_KEY", "test")
os.environ.setdefault("PAYSTACK_PUBLIC_KEY", "test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379")

# Provide a valid Fernet key for the crypto module
from cryptography.fernet import Fernet as _Fernet
os.environ["DATA_ENCRYPTION_KEY"] = _Fernet.generate_key().decode()

# Mail env vars for testing
os.environ["MAIL_SERVER"] = "smtp.test.local"
os.environ["MAIL_PORT"] = "587"
os.environ["MAIL_USERNAME"] = "testuser"
os.environ["MAIL_PASSWORD"] = "testpass"
os.environ["MAIL_FROM"] = "noreply@test.local"
os.environ["APP_BASE_URL"] = "http://localhost:5000"

# ---------------------------------------------------------------------------
# Now safe to import application modules
# ---------------------------------------------------------------------------
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from database import Base
from models import User

# We need to patch SessionLocal before importing app so routes use our test DB
_test_engine = create_engine("sqlite:///:memory:")
_TestSession = sessionmaker(bind=_test_engine, autoflush=False, autocommit=False)

# SQLite doesn't support some PG features; enable WAL for concurrency
@event.listens_for(_test_engine, "connect")
def _set_sqlite_pragma(dbapi_conn, connection_record):
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.close()


@pytest.fixture(autouse=True)
def _setup_db(monkeypatch):
    """Create tables fresh for every test and patch SessionLocal."""
    Base.metadata.create_all(_test_engine)

    # Patch database.SessionLocal used by app.create_db_session
    import database
    monkeypatch.setattr(database, "SessionLocal", _TestSession)

    # Also reload mail config constants in app module
    import app as app_module
    monkeypatch.setattr(app_module, "MAIL_SERVER", "smtp.test.local")
    monkeypatch.setattr(app_module, "MAIL_FROM", "noreply@test.local")
    monkeypatch.setattr(app_module, "APP_BASE_URL", "http://localhost:5000")

    yield

    Base.metadata.drop_all(_test_engine)


@pytest.fixture
def client():
    from app import app
    app.config["TESTING"] = True
    app.config["SERVER_NAME"] = "localhost:5000"
    with app.test_client() as c:
        yield c


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _register_user(client, username="alice", email="alice@example.com",
                   password="Secret123"):
    """POST to /register with valid form data (patches SMTP)."""
    from crypto import encrypt_str, encrypt_int
    with patch("app.send_verification_email", return_value=True) as mock_send:
        resp = client.post("/register", data={
            "username": username,
            "email": email,
            "gender": "female",
            "password": password,
            "confirm": password,
            "kdf_salt": "a" * 32,
            "encrypted_dek": "b" * 64,
            "recovery_encrypted_dek": "c" * 64,
        }, follow_redirects=False)
    return resp, mock_send


def _get_user(username="alice"):
    """Fetch the user row directly from the test DB."""
    db = _TestSession()
    try:
        return db.query(User).filter(User.username == username).first()
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
class TestRegistration:
    def test_register_creates_unverified_user_with_token(self, client):
        resp, mock_send = _register_user(client)
        user = _get_user("alice")

        assert user is not None
        assert user.is_verified is False
        assert user.verification_token is not None
        assert len(user.verification_token) == 64

    def test_register_sends_verification_email(self, client):
        resp, mock_send = _register_user(client)
        mock_send.assert_called_once()
        args = mock_send.call_args
        assert args[0][0] == "alice@example.com"  # to_email
        assert len(args[0][1]) == 64  # token

    def test_register_does_not_log_user_in(self, client):
        """After registration, user should NOT be logged in (must verify first)."""
        resp, _ = _register_user(client)
        # The response should render the login template with a verification notice
        assert resp.status_code == 200
        assert b"verification link" in resp.data.lower() or b"verify" in resp.data.lower()


class TestVerifyEmail:
    def test_valid_token_verifies_user(self, client):
        _register_user(client)
        user = _get_user("alice")
        token = user.verification_token

        resp = client.get(f"/verify-email/{token}")
        assert resp.status_code == 200
        assert b"verified" in resp.data.lower()

        # Re-fetch: should be verified, token cleared
        user = _get_user("alice")
        assert user.is_verified is True
        assert user.verification_token is None

    def test_invalid_token_fails(self, client):
        resp = client.get("/verify-email/" + "x" * 64)
        assert resp.status_code == 200
        assert b"invalid" in resp.data.lower() or b"already been used" in resp.data.lower()

    def test_short_token_fails(self, client):
        resp = client.get("/verify-email/tooshort")
        assert resp.status_code == 200
        assert b"invalid" in resp.data.lower()

    def test_reuse_token_fails(self, client):
        _register_user(client)
        user = _get_user("alice")
        token = user.verification_token

        # First use: success
        client.get(f"/verify-email/{token}")
        # Second use: fail
        resp = client.get(f"/verify-email/{token}")
        assert b"invalid" in resp.data.lower() or b"already been used" in resp.data.lower()


class TestLoginEnforcesVerification:
    def test_unverified_user_cannot_login(self, client):
        _register_user(client)
        resp = client.post("/login", data={
            "username": "alice",
            "password": "Secret123",
        })
        assert resp.status_code == 200
        assert b"verify" in resp.data.lower()
        # Should show resend button
        assert b"resend-verification" in resp.data.lower()

    def test_verified_user_can_login(self, client):
        _register_user(client)
        user = _get_user("alice")
        token = user.verification_token
        client.get(f"/verify-email/{token}")

        resp = client.post("/login", data={
            "username": "alice",
            "password": "Secret123",
        }, follow_redirects=False)
        # Should redirect to index on success
        assert resp.status_code == 302
        assert "/" in resp.headers.get("Location", "")


class TestResendVerification:
    def test_resend_rotates_token(self, client):
        _register_user(client)
        user = _get_user("alice")
        old_token = user.verification_token

        with patch("app.send_verification_email", return_value=True) as mock_send:
            resp = client.post("/resend-verification", data={"username": "alice"})

        assert resp.status_code == 200
        user = _get_user("alice")
        assert user.verification_token != old_token
        assert len(user.verification_token) == 64
        mock_send.assert_called_once()

    def test_resend_for_verified_user_says_already_verified(self, client):
        _register_user(client)
        user = _get_user("alice")
        client.get(f"/verify-email/{user.verification_token}")

        resp = client.post("/resend-verification", data={"username": "alice"})
        assert b"already verified" in resp.data.lower()

    def test_resend_for_unknown_user_does_not_reveal(self, client):
        resp = client.post("/resend-verification", data={"username": "nobody"})
        assert resp.status_code == 200
        # Should not reveal whether user exists
        assert b"if that account exists" in resp.data.lower()


class TestGenerateVerificationToken:
    def test_token_length_and_hex(self):
        from app import generate_verification_token
        token = generate_verification_token()
        assert len(token) == 64
        int(token, 16)  # should not raise


class TestSendVerificationEmail:
    @patch("smtplib.SMTP")
    def test_sends_email_via_smtp(self, mock_smtp_cls):
        mock_server = MagicMock()
        mock_smtp_cls.return_value = mock_server

        from app import send_verification_email
        result = send_verification_email("user@example.com", "a" * 64)

        assert result is True
        mock_smtp_cls.assert_called_once_with("smtp.test.local", 587, timeout=10)
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with("testuser", "testpass")
        mock_server.sendmail.assert_called_once()
        mock_server.quit.assert_called_once()

        # Check email content includes the verification URL
        call_args = mock_server.sendmail.call_args
        raw_msg = call_args[0][2]
        assert "verify-email/" in raw_msg
        assert "a" * 64 in raw_msg

    @patch("smtplib.SMTP", side_effect=Exception("Connection refused"))
    def test_returns_false_on_smtp_error(self, mock_smtp_cls):
        from app import send_verification_email
        result = send_verification_email("user@example.com", "a" * 64)
        assert result is False
