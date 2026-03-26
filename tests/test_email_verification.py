"""
Tests for the email verification flow.

Runs against a SQLite in-memory database so no external Postgres is needed.
Patches SMTP so no real email is sent during tests.
"""

import os
import smtplib
import socket
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


class TestResolveSmtpIpv4:
    """Tests for the _resolve_smtp_ipv4 helper that forces IPv4 on Railway."""

    @patch("app.socket.getaddrinfo")
    def test_returns_ipv4_address(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 587)),
        ]
        from app import _resolve_smtp_ipv4
        result = _resolve_smtp_ipv4("smtp.example.com", 587)
        assert result == "93.184.216.34"
        mock_getaddrinfo.assert_called_once_with(
            "smtp.example.com", 587, socket.AF_INET, socket.SOCK_STREAM,
        )

    @patch("app.socket.getaddrinfo", side_effect=socket.gaierror("DNS failed"))
    def test_falls_back_to_hostname_on_dns_failure(self, mock_getaddrinfo):
        from app import _resolve_smtp_ipv4
        result = _resolve_smtp_ipv4("smtp.example.com", 587)
        assert result == "smtp.example.com"

    @patch("app.socket.getaddrinfo", return_value=[])
    def test_falls_back_to_hostname_on_empty_result(self, mock_getaddrinfo):
        from app import _resolve_smtp_ipv4
        result = _resolve_smtp_ipv4("smtp.example.com", 587)
        assert result == "smtp.example.com"


class TestIPv4SMTPClasses:
    """Tests for _IPv4SMTP and _IPv4SMTP_SSL socket-level IPv4 enforcement."""

    @patch("app.socket.getaddrinfo")
    @patch("app.socket.socket")
    def test_ipv4_smtp_get_socket_forces_af_inet(self, mock_socket_cls, mock_getaddrinfo):
        """_IPv4SMTP._get_socket must call getaddrinfo with AF_INET."""
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 587)),
        ]
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        from app import _IPv4SMTP
        smtp = _IPv4SMTP.__new__(_IPv4SMTP)
        sock = smtp._get_socket("smtp.example.com", 587, 10)

        mock_getaddrinfo.assert_called_once_with(
            "smtp.example.com", 587, socket.AF_INET, socket.SOCK_STREAM,
        )
        mock_socket_cls.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM, 6)
        mock_sock.settimeout.assert_called_once_with(10)
        mock_sock.connect.assert_called_once_with(("93.184.216.34", 587))
        assert sock is mock_sock

    @patch("app.socket.getaddrinfo", return_value=[])
    def test_ipv4_smtp_raises_on_no_ipv4(self, mock_getaddrinfo):
        """_IPv4SMTP._get_socket raises OSError when no IPv4 address found."""
        from app import _IPv4SMTP
        smtp = _IPv4SMTP.__new__(_IPv4SMTP)
        with pytest.raises(OSError, match="No IPv4 address found"):
            smtp._get_socket("smtp.example.com", 587, 10)

    @patch("app.socket.getaddrinfo")
    @patch("app.socket.socket")
    def test_ipv4_smtp_ssl_get_socket_forces_af_inet(self, mock_socket_cls, mock_getaddrinfo):
        """_IPv4SMTP_SSL._get_socket must call getaddrinfo with AF_INET."""
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 465)),
        ]
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_tls_sock = MagicMock()

        from app import _IPv4SMTP_SSL
        smtp = _IPv4SMTP_SSL.__new__(_IPv4SMTP_SSL)
        smtp.context = MagicMock()
        smtp.context.wrap_socket.return_value = mock_tls_sock

        sock = smtp._get_socket("smtp.example.com", 465, 10)

        mock_getaddrinfo.assert_called_once_with(
            "smtp.example.com", 465, socket.AF_INET, socket.SOCK_STREAM,
        )
        mock_sock.connect.assert_called_once_with(("93.184.216.34", 465))
        smtp.context.wrap_socket.assert_called_once_with(
            mock_sock, server_hostname="smtp.example.com",
        )
        assert sock is mock_tls_sock

    @patch("app.socket.getaddrinfo", return_value=[])
    def test_ipv4_smtp_ssl_raises_on_no_ipv4(self, mock_getaddrinfo):
        """_IPv4SMTP_SSL._get_socket raises OSError when no IPv4 address found."""
        from app import _IPv4SMTP_SSL
        smtp = _IPv4SMTP_SSL.__new__(_IPv4SMTP_SSL)
        smtp.context = None
        with pytest.raises(OSError, match="No IPv4 address found"):
            smtp._get_socket("smtp.example.com", 465, 10)


class TestSendVerificationEmail:
    @patch("app._resolve_smtp_ipv4", return_value="1.2.3.4")
    @patch("app._IPv4SMTP")
    def test_sends_email_via_smtp(self, mock_smtp_cls, mock_resolve):
        mock_server = MagicMock()
        mock_smtp_cls.return_value = mock_server

        from app import send_verification_email
        result = send_verification_email("user@example.com", "a" * 64)

        assert result is True
        mock_resolve.assert_called_once_with("smtp.test.local", 587)
        mock_smtp_cls.assert_called_once_with("1.2.3.4", 587, timeout=10)
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with("testuser", "testpass")
        mock_server.sendmail.assert_called_once()
        mock_server.quit.assert_called_once()

        # Check email content includes the verification URL
        call_args = mock_server.sendmail.call_args
        raw_msg = call_args[0][2]
        assert "verify-email/" in raw_msg
        assert "a" * 64 in raw_msg

    @patch("app._resolve_smtp_ipv4", return_value="1.2.3.4")
    @patch("app._IPv4SMTP", side_effect=Exception("Connection refused"))
    def test_returns_false_on_smtp_error(self, mock_smtp_cls, mock_resolve):
        from app import send_verification_email
        result = send_verification_email("user@example.com", "a" * 64)
        assert result is False

    def test_returns_false_when_mail_server_not_set(self, monkeypatch):
        import app as app_module
        monkeypatch.setattr(app_module, "MAIL_SERVER", "")
        result = app_module.send_verification_email("user@example.com", "a" * 64)
        assert result is False

    def test_returns_false_when_credentials_missing(self, monkeypatch):
        import app as app_module
        monkeypatch.setattr(app_module, "MAIL_USERNAME", "")
        monkeypatch.setattr(app_module, "MAIL_PASSWORD", "")
        result = app_module.send_verification_email("user@example.com", "a" * 64)
        assert result is False

    @patch("app._resolve_smtp_ipv4", return_value="1.2.3.4")
    @patch("app._IPv4SMTP")
    def test_returns_false_on_auth_error(self, mock_smtp_cls, mock_resolve):
        mock_server = MagicMock()
        mock_smtp_cls.return_value = mock_server
        mock_server.login.side_effect = smtplib.SMTPAuthenticationError(535, b"Auth failed")

        from app import send_verification_email
        result = send_verification_email("user@example.com", "a" * 64)
        assert result is False

    @patch("app._resolve_smtp_ipv4", return_value="1.2.3.4")
    @patch("app._IPv4SMTP_SSL")
    def test_uses_ipv4_smtp_ssl_on_port_465(self, mock_ssl_cls, mock_resolve, monkeypatch):
        """Port 465 should use _IPv4SMTP_SSL instead of _IPv4SMTP."""
        import app as app_module
        monkeypatch.setattr(app_module, "MAIL_PORT", 465)
        mock_server = MagicMock()
        mock_ssl_cls.return_value = mock_server

        result = app_module.send_verification_email("user@example.com", "a" * 64)

        assert result is True
        mock_ssl_cls.assert_called_once_with("1.2.3.4", 465, timeout=10)
        mock_server.login.assert_called_once()
        mock_server.sendmail.assert_called_once()
        mock_server.quit.assert_called_once()


class TestRegistrationEmailFeedback:
    """Registration should show different messages based on whether email was sent."""

    def test_registration_shows_success_when_email_sent(self, client):
        """When email sends successfully, user sees 'check your email'."""
        resp, mock_send = _register_user(client)  # mock returns True
        assert resp.status_code == 200
        assert b"check your email" in resp.data.lower()
        # Should NOT show resend button when email was sent
        assert b"couldn" not in resp.data.lower()

    def test_registration_shows_resend_when_email_fails(self, client):
        """When email fails, user sees failure message and resend option."""
        with patch("app.send_verification_email", return_value=False):
            resp = client.post("/register", data={
                "username": "bob",
                "email": "bob@example.com",
                "gender": "male",
                "password": "Secret123",
                "confirm": "Secret123",
                "kdf_salt": "a" * 32,
                "encrypted_dek": "b" * 64,
                "recovery_encrypted_dek": "c" * 64,
            }, follow_redirects=False)
        assert resp.status_code == 200
        assert b"couldn" in resp.data.lower()  # "couldn't send"
        assert b"resend-verification" in resp.data.lower()


class TestResendVerificationFeedback:
    """Resend route should show different messages based on email result."""

    def test_resend_shows_failure_message_when_email_fails(self, client):
        _register_user(client)
        with patch("app.send_verification_email", return_value=False):
            resp = client.post("/resend-verification", data={"username": "alice"})
        assert resp.status_code == 200
        assert b"couldn" in resp.data.lower()
        assert b"resend-verification" in resp.data.lower()

    def test_resend_shows_success_message_when_email_sent(self, client):
        _register_user(client)
        with patch("app.send_verification_email", return_value=True):
            resp = client.post("/resend-verification", data={"username": "alice"})
        assert resp.status_code == 200
        assert b"new verification email has been sent" in resp.data.lower()


class TestSmtpPrintLogging:
    """Verify that send_verification_email emits print-level stdout/stderr lines."""

    @patch("app._resolve_smtp_ipv4", return_value="1.2.3.4")
    @patch("app._IPv4SMTP")
    def test_success_path_prints_to_stdout(self, mock_smtp_cls, mock_resolve, capsys):
        mock_server = MagicMock()
        mock_smtp_cls.return_value = mock_server

        from app import send_verification_email
        result = send_verification_email("user@example.com", "a" * 64)
        assert result is True

        captured = capsys.readouterr()
        assert "[EMAIL] send_verification_email called" in captured.out
        assert "[EMAIL] Resolving SMTP host" in captured.out
        assert "[EMAIL] Connecting to SMTP server" in captured.out
        assert "[EMAIL] STARTTLS on" in captured.out
        assert "[EMAIL] STARTTLS completed" in captured.out
        assert "[EMAIL] Connected. Logging in" in captured.out
        assert "[EMAIL] Login successful. Sending email" in captured.out
        assert "[EMAIL] SUCCESS" in captured.out

    def test_missing_config_prints_to_stderr(self, monkeypatch, capsys):
        import app as app_module
        monkeypatch.setattr(app_module, "MAIL_SERVER", "")
        app_module.send_verification_email("user@example.com", "a" * 64)

        captured = capsys.readouterr()
        assert "[EMAIL] send_verification_email called" in captured.out
        assert "[EMAIL] FAIL: Mail not configured" in captured.err

    def test_missing_credentials_prints_to_stderr(self, monkeypatch, capsys):
        import app as app_module
        monkeypatch.setattr(app_module, "MAIL_USERNAME", "")
        monkeypatch.setattr(app_module, "MAIL_PASSWORD", "")
        app_module.send_verification_email("user@example.com", "a" * 64)

        captured = capsys.readouterr()
        assert "[EMAIL] FAIL: Missing credentials" in captured.err

    @patch("app._resolve_smtp_ipv4", return_value="1.2.3.4")
    @patch("app._IPv4SMTP")
    def test_auth_error_prints_to_stderr(self, mock_smtp_cls, mock_resolve, capsys):
        mock_server = MagicMock()
        mock_smtp_cls.return_value = mock_server
        mock_server.login.side_effect = smtplib.SMTPAuthenticationError(535, b"Auth failed")

        from app import send_verification_email
        send_verification_email("user@example.com", "a" * 64)

        captured = capsys.readouterr()
        assert "[EMAIL] FAIL: SMTP auth error" in captured.err

    @patch("app._resolve_smtp_ipv4", return_value="1.2.3.4")
    @patch("app._IPv4SMTP", side_effect=smtplib.SMTPException("Connection refused"))
    def test_smtp_exception_prints_to_stderr(self, mock_smtp_cls, mock_resolve, capsys):
        from app import send_verification_email
        send_verification_email("user@example.com", "a" * 64)

        captured = capsys.readouterr()
        assert "[EMAIL] FAIL: SMTP error" in captured.err

    @patch("app._resolve_smtp_ipv4", return_value="1.2.3.4")
    @patch("app._IPv4SMTP", side_effect=RuntimeError("Something unexpected"))
    def test_unexpected_error_prints_to_stderr(self, mock_smtp_cls, mock_resolve, capsys):
        from app import send_verification_email
        send_verification_email("user@example.com", "a" * 64)

        captured = capsys.readouterr()
        assert "[EMAIL] FAIL: Unexpected error" in captured.err

    @patch("app.socket.getaddrinfo")
    def test_resolve_ipv4_prints_on_success(self, mock_getaddrinfo, capsys):
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 587)),
        ]
        from app import _resolve_smtp_ipv4
        _resolve_smtp_ipv4("smtp.example.com", 587)

        captured = capsys.readouterr()
        assert "[EMAIL] Resolved SMTP host smtp.example.com to IPv4 address 93.184.216.34" in captured.out

    @patch("app.socket.getaddrinfo", side_effect=socket.gaierror("DNS failed"))
    def test_resolve_ipv4_prints_on_dns_failure(self, mock_getaddrinfo, capsys):
        from app import _resolve_smtp_ipv4
        _resolve_smtp_ipv4("smtp.example.com", 587)

        captured = capsys.readouterr()
        assert "[EMAIL] IPv4 DNS resolution failed" in captured.err
