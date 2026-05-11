"""
memory/extractor.py  —  LLM-based fact extraction and safety classification.

After every assistant reply this module:
  1. Calls the LLM with a compact extraction prompt to pull facts from the
     latest user message (not the assistant reply — we learn about the USER).
  2. Classifies any safety triggers in the user message.
  3. Detects resolution signals ("I feel better now") and marks stale facts
     resolved via db.resolve_facts_by_keyword.
  4. Persists new facts with embeddings via db.insert_fact.

Token budget: the extraction call uses ~120 prompt tokens + a tiny
JSON reply.  It is skipped entirely when DATABASE_URL is not configured.
"""

import json
import logging
import os
from typing import Optional

from openai import OpenAI

from memory import db, embeddings

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Safety trigger categories and their keyword signals.
# The LLM is the primary classifier; this dict is a fast pre-screen.
# ---------------------------------------------------------------------------
SAFETY_KEYWORDS: dict[str, list[str]] = {
    "self_harm": [
        "suicide", "suicidal", "kill myself", "end my life",
        "self harm", "self-harm", "hurt myself", "cutting myself",
        "overdose", "don't want to live",
    ],
    "violence_planning": [
        "school shooting", "mass shooting", "bomb", "attack plan",
        "kill plan", "how to kill", "weapon",
    ],
    "csam": [
        "child porn", "csam", "underage sex", "minor",
    ],
}

# Resolution signals: if a user message contains any of these phrases we
# attempt to resolve related stored facts rather than add new ones.
RESOLUTION_SIGNALS: list[tuple[str, list[str]]] = [
    # (keyword to resolve in DB,  triggers that indicate resolution)
    ("suicide",    ["feel better", "got help", "i'm ok", "doing well", "i am fine", "therapy"]),
    ("suicidal",   ["feel better", "got help", "i'm ok", "doing well", "i am fine"]),
    ("self harm",  ["stopped", "recovered", "doing better", "in therapy"]),
    ("depressed",  ["feel better", "feeling better", "improved", "therapy helping"]),
]

# ---------------------------------------------------------------------------
# Extraction prompt
# ---------------------------------------------------------------------------

_EXTRACTION_SYSTEM = """You extract factual memory from a user message.
Return ONLY a JSON object with this exact shape (no markdown, no extra keys):
{
  "facts": [
    {
      "text": "<one short factual sentence about the user>",
      "owner": "user",
      "scope": "user_private",
      "temporal_tag": "current",
      "importance": 1.0
    }
  ],
  "resolution_signals": ["<keyword to resolve if the message implies a past issue is now resolved>"]
}

Rules:
- Extract facts about the USER only. Never invent facts about the character.
- owner is always "user" for facts from the user's message.
- scope is "user_private" by default. Use "cross_character" only for persistent
  identity facts (name, age, city).
- temporal_tag: "current" if the fact is true now, "historical" if the user
  is describing the past, "resolved" if the user says something is no longer true.
- importance: 1.0 default, 2.0 for emotional distress, 3.0 for crisis signals.
- Return an empty facts list [] if there is nothing worth storing.
- resolution_signals: list of plain keywords (e.g. "suicide") that the user
  has indicated are now resolved. Empty list [] if none."""


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def extract_and_store(
    user_message: str,
    user_id: str,
    character_id: Optional[str],
    conversation_id: Optional[str],
    llm_client: OpenAI,
    model: str,
) -> list[int]:
    """
    Extract facts from *user_message*, classify safety triggers, and persist
    everything to the database. Returns a list of inserted memory_fact_ids.

    If DATABASE_URL is absent the function is a no-op (returns []).
    This keeps the app runnable without a DB during local dev.
    """
    if not os.environ.get("DATABASE_URL"):
        return []

    inserted_ids: list[int] = []

    # --- 1. Safety pre-screen (zero extra tokens) ---
    _handle_safety_triggers(user_message, user_id, conversation_id)

    # --- 2. Resolution detection (keyword-only, zero extra tokens) ---
    _handle_resolution_signals(user_message, user_id)

    # --- 3. LLM extraction ---
    raw = _call_extraction_llm(user_message, llm_client, model)
    if raw is None:
        return inserted_ids

    # --- 4. Process resolution signals from LLM output ---
    for keyword in raw.get("resolution_signals", []):
        if keyword and isinstance(keyword, str):
            count = db.resolve_facts_by_keyword(user_id, keyword.strip())
            log.debug("extractor: resolved %d facts for keyword '%s'", count, keyword)

    # --- 5. Persist new facts ---
    for fact in raw.get("facts", []):
        text = (fact.get("text") or "").strip()
        if not text:
            continue

        owner       = fact.get("owner", "user")
        scope       = fact.get("scope", "user_private")
        temporal    = fact.get("temporal_tag", "current")
        importance  = float(fact.get("importance", 1.0))

        # Embed the fact text for semantic retrieval.
        embedding = embeddings.encode(text)

        fact_id = db.insert_fact(
            user_id=user_id,
            fact_text=text,
            fact_owner=owner,
            scope=scope,
            temporal_tag=temporal,
            character_id=character_id,
            confidence_score=1.0,
            importance_score=importance,
            # 'current' facts decay slowly; 'historical' faster.
            decay_rate=0.005 if temporal == "current" else 0.02,
            conversation_id=conversation_id,
            embedding=embedding,
        )
        inserted_ids.append(fact_id)
        log.debug("extractor: stored fact #%d: %s", fact_id, text[:60])

    return inserted_ids


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _handle_safety_triggers(
    message: str,
    user_id: str,
    conversation_id: Optional[str],
) -> None:
    """
    Keyword-scan the message and write safety_global facts for any matches.
    This runs before the LLM call so safety flags are never skipped even
    if the LLM extraction call fails.
    """
    lower = message.lower()
    for category, keywords in SAFETY_KEYWORDS.items():
        if any(kw in lower for kw in keywords):
            # Use a short summary as the stored fact text.
            summary = f"User triggered safety category: {category}"
            embedding = embeddings.encode(summary)
            try:
                db.insert_fact(
                    user_id=user_id,
                    fact_text=summary,
                    fact_owner="system",
                    scope="safety_global",
                    temporal_tag="current",
                    character_id=None,   # safety facts have no character scope
                    confidence_score=1.0,
                    importance_score=10.0,
                    decay_rate=0.0,      # safety flags never auto-decay
                    trigger_tags=[category],
                    conversation_id=conversation_id,
                    embedding=embedding,
                )
                log.warning(
                    "extractor: safety flag written [%s] for user %s",
                    category, user_id,
                )
            except Exception as exc:
                # Never let a DB error block the user's chat response.
                log.error("extractor: failed to write safety flag: %s", exc)


def _handle_resolution_signals(message: str, user_id: str) -> None:
    """
    Keyword-based resolution: if the user says they feel better etc.,
    mark related non-safety facts as resolved before the LLM runs.
    """
    lower = message.lower()
    for keyword, signals in RESOLUTION_SIGNALS:
        if any(sig in lower for sig in signals):
            count = db.resolve_facts_by_keyword(user_id, keyword)
            if count:
                log.info(
                    "extractor: resolved %d '%s' facts via resolution signal",
                    count, keyword,
                )


def _call_extraction_llm(
    user_message: str,
    client: OpenAI,
    model: str,
) -> Optional[dict]:
    """
    Call the LLM with the extraction prompt and return the parsed JSON dict.
    Returns None on any error to degrade gracefully.
    """
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": _EXTRACTION_SYSTEM},
                {"role": "user",   "content": user_message},
            ],
            max_tokens=300,
            # Disable thinking tokens for this call — we want pure JSON output.
            extra_body={"chat_template_kwargs": {"enable_thinking": False}},
        )
        raw_text = response.choices[0].message.content or ""
        # Strip any accidental markdown fences.
        raw_text = raw_text.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
        return json.loads(raw_text)
    except json.JSONDecodeError as exc:
        log.warning("extractor: LLM returned invalid JSON — %s", exc)
        return None
    except Exception as exc:
        log.warning("extractor: LLM extraction call failed — %s", exc)
        return None
