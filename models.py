import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    Text,
    String,
    DateTime,
    ForeignKey,
    CheckConstraint,
    LargeBinary,
    Integer,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from database import Base
from crypto import encrypt_str, decrypt_str, encrypt_int, decrypt_int


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String, unique=True, nullable=False)       # plaintext
    password_hash = Column(Text, nullable=False)                 # Argon2/bcrypt

    # encrypted fields map to the existing *_enc columns (BYTEA / `bytea`)
    email_enc = Column("email_enc", LargeBinary, nullable=False)
    gender_enc = Column("gender_enc", LargeBinary, nullable=False)
    coins_enc = Column("coins_enc", LargeBinary, nullable=False)

    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # relationships
    messages = relationship("ChatMessage", back_populates="user", cascade="all, delete-orphan")
    coin_transactions = relationship("CoinTransaction", back_populates="user", cascade="all, delete-orphan")

    # convenience properties for encrypted fields

    @property
    def email(self) -> str:
        return decrypt_str(self.email_enc)

    @email.setter
    def email(self, value: str) -> None:
        self.email_enc = encrypt_str(value)

    @property
    def gender(self) -> str:
        return decrypt_str(self.gender_enc)

    @gender.setter
    def gender(self, value: str) -> None:
        self.gender_enc = encrypt_str(value)

    @property
    def coins(self) -> int:
        return decrypt_int(self.coins_enc)

    @coins.setter
    def coins(self, value: int) -> None:
        self.coins_enc = encrypt_int(value)


class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    role = Column(String, nullable=False)  # 'user' or 'agent'
    content_enc = Column("content_enc", LargeBinary, nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        CheckConstraint("role IN ('user', 'agent')", name="chat_messages_role_check"),
    )

    user = relationship("User", back_populates="messages")

    @property
    def content(self) -> str:
        return decrypt_str(self.content_enc)

    @content.setter
    def content(self, value: str) -> None:
        self.content_enc = encrypt_str(value)


class CoinTransaction(Base):
    __tablename__ = "coin_transactions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    delta_enc = Column("delta_enc", LargeBinary, nullable=False)
    reason_enc = Column("reason_enc", LargeBinary, nullable=False)

    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    user = relationship("User", back_populates="coin_transactions")

    @property
    def delta(self) -> int:
        return decrypt_int(self.delta_enc)

    @delta.setter
    def delta(self, value: int) -> None:
        self.delta_enc = encrypt_int(value)

    @property
    def reason(self) -> str:
        return decrypt_str(self.reason_enc)

    @reason.setter
    def reason(self, value: str) -> None:
        self.reason_enc = encrypt_str(value)
