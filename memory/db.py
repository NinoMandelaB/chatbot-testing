"""
memory/db.py  —  Database access layer for the memory system.

All raw SQL lives here. The rest of the memory package never imports
psycopg2 directly — it calls functions from this module only.

Connection is created once per process from the DATABASE_URL env var
(standard Railway Postgres URL format).
"""
import os
import logging
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Optional

import psycopg2
import psycopg2.extras  # for RealDictCursor

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------

_conn: Optional[psycopg2.extensions.connection] = None


def get_conn() -> psycopg2.extensions.connection:
    """Return a module-level persistent connection, re-connecting if closed."""
    global _conn
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL env var is not set.")
    if _conn is None or _conn.closed:
        _conn = psycopg2.connect(url, cursor_factory=psycopg2.extras.RealDictCursor)
        _conn.autocommit = False
        log.info("memory.db: new database connection established")
    return _conn


@contextmanager
def cursor():
    """Context manager that yields a cursor and commits on success."""
    conn = get_conn()
    cur = conn.cursor()
    try:
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()


# ---------------------------------------------------------------------------
# Writes
# ---------------------------------------------------------------------------

def insert_fact(
    user_id: str,
    fact_text: str,
    fact_owner: str,       # 'user' | 'character' | 'system'
    scope: str,            # 'user_private' | 'cross_character' | 'safety_global'
    temporal_tag: str,     # 'current' | 'historical' | 'resolved'
    character_id: Optional[str] = None,
    confidence_score: float = 1.0,
    importance_score: float = 1.0,
    decay_rate: float = 0.005,
    trigger_tags: Optional[list] = None,
    conversation_id: Optional[str] = None,
    source_message_id: Optional[str] = None,
    embedding: Optional[list] = None,   # 384-dim float list
) -> int:
    """Insert a new memory fact and return its memory_fact_id."""
    tags = trigger_tags or []
    now = datetime.now(timezone.utc)
    with cursor() as cur:
        cur.execute("""
            INSERT INTO memory_facts (
                user_id, character_id, fact_text, fact_owner, scope,
                temporal_tag, as_of, confidence_score, importance_score,
                decay_rate, trigger_tags, conversation_id, source_message_id,
                embedding, extracted_at
            ) VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s
            ) RETURNING memory_fact_id
        """, (
            user_id, character_id, fact_text, fact_owner, scope,
            temporal_tag, now, confidence_score, importance_score,
            decay_rate, tags, conversation_id, source_message_id,
            embedding, now,
        ))
        row = cur.fetchone()
        return row["memory_fact_id"]


def resolve_facts_by_keyword(user_id: str, keyword: str) -> int:
    """
    Mark all non-safety facts containing *keyword* as resolved.
    Returns the number of rows updated.
    Safety-global facts are intentionally excluded.
    """
    with cursor() as cur:
        cur.execute("""
            UPDATE memory_facts
            SET temporal_tag = 'resolved',
                resolved_at  = NOW(),
                confidence_score = 0.05
            WHERE user_id = %s
              AND fact_text ILIKE %s
              AND scope != 'safety_global'
              AND temporal_tag != 'resolved'
              AND is_active = TRUE
        """, (user_id, f"%{keyword}%"))
        return cur.rowcount


def touch_last_used(fact_ids: list[int]) -> None:
    """Update last_used_at for facts that were injected into the prompt."""
    if not fact_ids:
        return
    with cursor() as cur:
        cur.execute("""
            UPDATE memory_facts
            SET last_used_at = NOW()
            WHERE memory_fact_id = ANY(%s)
        """, (fact_ids,))


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------

def fetch_safety_flags(user_id: str) -> list[dict]:
    """
    Fetch all active safety-global facts for a user.
    Called on every request regardless of character.
    """
    with cursor() as cur:
        cur.execute("""
            SELECT memory_fact_id, trigger_tags, fact_text, created_at
            FROM memory_facts
            WHERE user_id = %s
              AND scope = 'safety_global'
              AND is_active = TRUE
            ORDER BY importance_score DESC
            LIMIT 10
        """, (user_id,))
        return [dict(r) for r in cur.fetchall()]


def fetch_candidate_facts(
    user_id: str,
    character_id: Optional[str],
    exclude_resolved: bool = True,
) -> list[dict]:
    """
    Fetch all non-safety facts eligible for semantic ranking.
    Includes both user_private (for this character) and cross_character facts.
    """
    filters = "AND temporal_tag != 'resolved'" if exclude_resolved else ""
    with cursor() as cur:
        cur.execute(f"""
            SELECT
                memory_fact_id, fact_text, fact_owner, scope, temporal_tag,
                as_of, confidence_score, importance_score, decay_rate,
                trigger_tags, embedding
            FROM memory_facts
            WHERE user_id = %s
              AND scope != 'safety_global'
              AND is_active = TRUE
              AND (
                    (scope = 'user_private' AND character_id = %s)
                    OR scope = 'cross_character'
              )
              {filters}
            ORDER BY importance_score DESC, confidence_score DESC
            LIMIT 100
        """, (user_id, character_id))
        return [dict(r) for r in cur.fetchall()]


def fetch_facts_for_debug(
    user_id: Optional[str] = None,
    character_id: Optional[str] = None,
    limit: int = 200,
) -> list[dict]:
    """
    Flexible debug query used by the /memory/debug API endpoint.
    Filter behaviour:
      - both None       -> full table (up to `limit` rows)
      - user_id only    -> all facts for that user
      - character_id only -> all facts for that character across all users
      - both provided   -> facts matching both user AND character
    """
    conditions = ["is_active = TRUE"]
    params: list = []
    if user_id:
        conditions.append("user_id = %s")
        params.append(user_id)
    if character_id:
        conditions.append("character_id = %s")
        params.append(character_id)
    where_clause = " AND ".join(conditions)
    params.append(limit)
    with cursor() as cur:
        cur.execute(f"""
            SELECT
                memory_fact_id, user_id, character_id, fact_text, fact_owner,
                scope, temporal_tag, as_of, confidence_score, importance_score,
                trigger_tags, is_active, created_at
            FROM memory_facts
            WHERE {where_clause}
            ORDER BY created_at DESC
            LIMIT %s
        """, params)
        return [dict(r) for r in cur.fetchall()]


# ---------------------------------------------------------------------------
# Conversation summaries (hybrid memory — schema_v3.sql)
# ---------------------------------------------------------------------------

def upsert_summary(
    user_id: str,
    character_id: str,
    summary_text: str,
    turn_count: int,
) -> None:
    """
    Atomically replace the active summary for a (user_id, character_id) pair.
    Steps:
      1. Mark any existing active summary as inactive (keeps an audit trail).
      2. Insert the new summary as the single active record.
    The turn_count stored here is the CUMULATIVE total of user turns seen
    across all sessions — not just the current frontend history slice.
    """
    with cursor() as cur:
        # Deactivate the previous active summary (if any).
        cur.execute("""
            UPDATE conversation_summaries
            SET is_active = FALSE
            WHERE user_id = %s AND character_id = %s AND is_active = TRUE
        """, (user_id, character_id))
        # Insert the fresh summary.
        cur.execute("""
            INSERT INTO conversation_summaries
                (user_id, character_id, summary_text, turn_count, is_active)
            VALUES (%s, %s, %s, %s, TRUE)
        """, (user_id, character_id, summary_text, turn_count))


def fetch_summary(
    user_id: str,
    character_id: str,
) -> Optional[str]:
    """
    Return the active conversation summary text for a session, or None.
    Called by memory/retriever.py to prepend long-term context.
    """
    with cursor() as cur:
        cur.execute("""
            SELECT summary_text FROM conversation_summaries
            WHERE user_id = %s AND character_id = %s AND is_active = TRUE
            ORDER BY created_at DESC LIMIT 1
        """, (user_id, character_id))
        row = cur.fetchone()
        return row["summary_text"] if row else None


def fetch_summary_turn_count(
    user_id: str,
    character_id: str,
) -> int:
    """
    Return the cumulative turn_count stored in the active summary row.
    Used by memory/summariser.py to correctly compute when to trigger the
    next summary, regardless of how many messages the frontend is currently
    sending in its history slice.
    Returns 0 when no summary exists yet.
    """
    with cursor() as cur:
        cur.execute("""
            SELECT turn_count FROM conversation_summaries
            WHERE user_id = %s AND character_id = %s AND is_active = TRUE
            ORDER BY created_at DESC LIMIT 1
        """, (user_id, character_id))
        row = cur.fetchone()
        return int(row["turn_count"]) if row else 0
