import os
from sqlalchemy import create_engine, text, inspect
from sqlalchemy.orm import sessionmaker, DeclarativeBase

DATABASE_URL = os.getenv("DATABASE_URL")  # Railway injects this for Postgres


class Base(DeclarativeBase):
    pass


engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def run_migrations():
    """
    Lightweight migration helper that runs once at startup.
    Adds any columns that exist in models but not yet in the DB,
    and converts content_enc from bytea -> text if needed.
    """
    insp = inspect(engine)

    # --- users table: email verification columns --------------------------------
    if insp.has_table("users"):
        user_cols = {c["name"] for c in insp.get_columns("users")}

        with engine.begin() as conn:
            if "is_verified" not in user_cols:
                conn.execute(text(
                    'ALTER TABLE users '
                    'ADD COLUMN is_verified BOOLEAN NOT NULL DEFAULT FALSE'
                ))
                print("Migration: added is_verified to users")

            if "verification_token" not in user_cols:
                conn.execute(text(
                    'ALTER TABLE users '
                    'ADD COLUMN verification_token VARCHAR(64) UNIQUE'
                ))
                print("Migration: added verification_token to users")

    # --- chat_messages table --------------------------------------------------
    if insp.has_table("chat_messages"):
        cols = {c["name"] for c in insp.get_columns("chat_messages")}

        with engine.begin() as conn:
            # Add chat_session_id if missing
            if "chat_session_id" not in cols:
                conn.execute(text(
                    'ALTER TABLE chat_messages '
                    'ADD COLUMN chat_session_id VARCHAR(36)'
                ))
                print("Migration: added chat_session_id to chat_messages")

            # Fix content_enc type: if it's bytea, cast to text so
            # psycopg2 returns plain strings instead of memoryview.
            col_info = next(
                (c for c in insp.get_columns("chat_messages")
                 if c["name"] == "content_enc"),
                None,
            )
            if col_info and str(col_info["type"]).upper().startswith(("BYTEA", "LARGE")):
                conn.execute(text(
                    'ALTER TABLE chat_messages '
                    'ALTER COLUMN content_enc TYPE TEXT '
                    'USING encode(content_enc, \'escape\')'
                ))
                print("Migration: converted content_enc from bytea to text")
