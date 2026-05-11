"""
memory/retriever.py  —  Hybrid ranked retrieval and prompt block construction.

This module answers: "Given the current user message, what memory should
we inject into the prompt, and how compactly can we say it?"

Hybrid retrieval pipeline
--------------------------
1. Always fetch safety_global flags  (cheap DB query, no embedding needed).
2. Fetch the active conversation summary for this session (long-term context).
3. Fetch candidate facts for this user + character from the DB.
4. Score each candidate: decay the confidence score, then re-rank by
   cosine similarity to the current message embedding.
5. Split by fact_owner to keep user facts and character facts in separate
   labelled sections, preventing the LLM from confusing them.
6. Build the final [MEMORY]...[/MEMORY] block targeting ~200 tokens max:
     [SUMMARY] … [/SUMMARY]   ← long-term context from summariser.py
     About the user: …         ← semantic fact retrieval
     Character knows: …        ← semantic fact retrieval
"""

import logging
import math
from datetime import datetime, timezone
from typing import Optional

from memory import db, embeddings

log = logging.getLogger(__name__)

# Maximum facts injected per owner type.
_MAX_USER_FACTS     = 5
_MAX_CHAR_FACTS     = 3
# Facts below this effective confidence are not injected.
_CONFIDENCE_THRESHOLD = 0.25


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def build_memory_block(
    user_message: str,
    user_id: str,
    character_id: Optional[str],
) -> tuple[str, list[int]]:
    """
    Build the memory injection block for a prompt.

    Returns
    -------
    (block_text, used_fact_ids)
        block_text    — the [MEMORY]...[/MEMORY] string (empty string if no
                        facts are available or DATABASE_URL is not set).
        used_fact_ids — list of memory_fact_ids that were injected, so the
                        caller can update last_used_at via db.touch_last_used.
    """
    import os
    if not os.environ.get("DATABASE_URL"):
        return "", []

    try:
        return _build(user_message, user_id, character_id)
    except Exception as exc:
        # Never crash the main chat flow because of a memory error.
        log.error("retriever.build_memory_block failed: %s", exc)
        return "", []


# ---------------------------------------------------------------------------
# Internal logic
# ---------------------------------------------------------------------------

def _build(
    user_message: str,
    user_id: str,
    character_id: Optional[str],
) -> tuple[str, list[int]]:
    lines: list[str] = []
    used_ids: list[int] = []

    # --- Safety flags (always first, always present if they exist) ---
    safety_line = _build_safety_line(user_id)
    if safety_line:
        lines.append(safety_line)

    # --- Conversation summary (long-term context, hybrid layer) ---
    # Only available when both user_id and character_id are set.
    if user_id and character_id:
        try:
            summary = db.fetch_summary(user_id, character_id)
            if summary:
                lines.append(f"[SUMMARY]\n{summary}\n[/SUMMARY]")
        except Exception as exc:
            log.warning("retriever: could not fetch summary: %s", exc)

    # --- Semantic retrieval for regular facts ---
    candidates = db.fetch_candidate_facts(user_id, character_id)
    if not candidates:
        block = _wrap(lines)
        return block, used_ids

    # Encode the current user message for similarity scoring.
    query_vec = embeddings.encode(user_message)

    # Score and filter candidates.
    scored = _score_candidates(candidates, query_vec)

    # Split by owner to prevent LLM confusion.
    user_facts = [
        f for f in scored if f["fact"]["fact_owner"] == "user"
    ][:_MAX_USER_FACTS]
    char_facts = [
        f for f in scored if f["fact"]["fact_owner"] == "character"
    ][:_MAX_CHAR_FACTS]

    # Build the user-facts section.
    if user_facts:
        lines.append("About the user:")
        for item in user_facts:
            fact = item["fact"]
            age_hint = _age_hint(fact.get("as_of"))
            text = fact["fact_text"]
            lines.append(f"  - {text}{age_hint}")
            used_ids.append(fact["memory_fact_id"])

    # Build the character-knowledge section.
    if char_facts:
        lines.append("Character knows:")
        for item in char_facts:
            fact = item["fact"]
            lines.append(f"  - {fact['fact_text']}")
            used_ids.append(fact["memory_fact_id"])

    return _wrap(lines), used_ids


def _score_candidates(
    candidates: list[dict],
    query_vec: Optional[list],
) -> list[dict]:
    """
    Score each candidate by:
        score = effective_confidence * (0.5 + 0.5 * cosine_similarity)

    effective_confidence applies exponential decay based on fact age.
    Candidates below _CONFIDENCE_THRESHOLD are dropped.
    Returns list sorted descending by score.
    """
    scored = []
    for fact in candidates:
        eff_conf = _effective_confidence(fact)
        if eff_conf < _CONFIDENCE_THRESHOLD:
            continue

        # Semantic similarity boost (0.0 if no embeddings available).
        sim = 0.0
        if query_vec and fact.get("embedding"):
            sim = embeddings.cosine_similarity(query_vec, fact["embedding"])

        # Weight: confidence is primary, similarity is a 50% bonus.
        score = eff_conf * (0.5 + 0.5 * sim)
        scored.append({"fact": fact, "score": score})

    scored.sort(key=lambda x: x["score"], reverse=True)
    return scored


def _effective_confidence(fact: dict) -> float:
    """
    Apply exponential decay to the stored confidence_score.
        resolved facts    → 0.0  (never injected)
        historical facts  decay at decay_rate per day
        current facts     decay at decay_rate per day (much slower by default)
    """
    if fact.get("temporal_tag") == "resolved":
        return 0.0
    base = float(fact.get("confidence_score", 1.0))
    rate = float(fact.get("decay_rate", 0.005))
    as_of = fact.get("as_of")
    if as_of is None:
        return base
    # Normalise timezone so subtraction works regardless of DB tz setting.
    now = datetime.now(timezone.utc)
    if as_of.tzinfo is None:
        as_of = as_of.replace(tzinfo=timezone.utc)
    days_old = max(0.0, (now - as_of).total_seconds() / 86400)
    decayed = base * math.exp(-rate * days_old)
    return max(0.0, min(1.0, decayed))


def _build_safety_line(user_id: str) -> str:
    """
    Fetch safety flags and return a compact single-line string.
    Only the category tag names are injected (not the full stored text)
    to keep token cost minimal (~15 tokens per request).
    """
    try:
        flags = db.fetch_safety_flags(user_id)
    except Exception as exc:
        log.warning("retriever: could not fetch safety flags: %s", exc)
        return ""
    if not flags:
        return ""
    # Flatten all trigger_tags from all flags, de-duplicate.
    all_tags: set[str] = set()
    for flag in flags:
        for tag in (flag.get("trigger_tags") or []):
            all_tags.add(tag)
    if not all_tags:
        return ""
    tags_str = ", ".join(sorted(all_tags))
    return (
        f"[SAFETY CONTEXT: This user has previously triggered safety "
        f"responses for: {tags_str}. Apply heightened caution for related topics.]"
    )


def _age_hint(as_of) -> str:
    """Return a short age string like ' (as of Jan 2025)' for temporal context."""
    if not as_of:
        return ""
    try:
        if as_of.tzinfo is None:
            as_of = as_of.replace(tzinfo=timezone.utc)
        return f" (as of {as_of.strftime('%b %Y')})"
    except Exception:
        return ""


def _wrap(lines: list[str]) -> str:
    """Wrap lines into the [MEMORY] block, or return empty string."""
    content = "\n".join(lines).strip()
    if not content:
        return ""
    return f"[MEMORY]\n{content}\n[/MEMORY]"
