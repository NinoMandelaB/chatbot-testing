"""
memory/extractor.py — LLM-based fact extraction and safety classification.

After every assistant reply this module:
 1. Keyword pre-screens the user message for GLOBAL safety violations and writes
    safety_global facts to the DB (zero extra LLM tokens).
 2. Calls the LLM with a dual-purpose prompt that:
    a. Extracts personal facts about the USER.
    b. Classifies GLOBAL safety violations missed by the keyword pre-screen
       (e.g. implicit threats like "I want to kill someone").
 3. Detects resolution signals and marks stale facts as resolved.
 4. Persists new facts with embeddings via db.insert_fact.

Important distinction:
- This extractor is for durable, cross-session memory.
- It should ONLY store severe real-world risks that should affect future chats.
- Per-chat roleplay hard blocks (e.g. adult incest fiction, bestiality fiction,
  fictional non-consent) should be handled by the runtime safety layer, NOT
  written into safety_global memory unless they also indicate a real-world
  severe safety concern.

Safety facts use scope='safety_global' so they are injected into every
future session regardless of character, giving the model contextual
awareness across sessions (e.g. user threatened violence → refuse gun
shop question even in an unrelated chat).

Token budget: ~200 prompt tokens + small JSON reply per turn.
Skipped entirely when DATABASE_URL is not configured.
"""

import json
import logging
import os
from typing import Optional

from openai import OpenAI

from memory import db, embeddings

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Safety keyword pre-screen
# ---------------------------------------------------------------------------
# Fast zero-token check run BEFORE the LLM call.
# Catches explicit, unambiguous GLOBAL safety triggers only.
# The LLM classifier (below) catches implicit threats the keywords miss.
#
# IMPORTANT:
# - Do NOT put generic adult sexual language here.
# - Do NOT put every roleplay hard-block here.
# - This list is only for things that should become durable, cross-session
#   safety_global memory.
# ---------------------------------------------------------------------------
SAFETY_KEYWORDS: dict[str, list[str]] = {
    "self_harm": [
        "suicide",
        "suicidal",
        "kill myself",
        "end my life",
        "self harm",
        "self-harm",
        "hurt myself",
        "cutting myself",
        "overdose",
        "don't want to live",
    ],
    "violence_planning": [
        "school shooting",
        "mass shooting",
        "attack plan",
        "kill plan",
        "how to kill",
        "i will kill",
        "i want to kill",
        "want to kill",
        "going to kill",
        "gonna kill",
        "planning to kill",
        "i'll kill",
        "murder someone",
        "i want to murder",
        "bomb",
        "weapon",
    ],
    "csam": [
        "child porn",
        "csam",
        "underage sex",
        "underage",
        "minor sexual",
        "schoolgirl",
        "schoolboy",
        "barely legal",
        "still developing",
        "perky young",
        "teen"  # only meaningful when sexual context is present; guarded below
    ],
}

# Extra sexual-context indicators used to avoid false positives such as
# "teen developer" or "schoolboy error".
CSAM_SEXUAL_CONTEXT_KEYWORDS = [
    "sex",
    "sexy",
    "nude",
    "naked",
    "fuck",
    "fucking",
    "horny",
    "turned on",
    "cum",
    "rape",
    "molest",
    "blowjob",
    "bj",
    "anal",
    "oral",
    "penetrat",
    "porn",
    "nsfw",
]

# Resolution signals: phrases that indicate a previously flagged issue is
# now resolved. Keyed by the DB keyword to mark as resolved.
RESOLUTION_SIGNALS: list[tuple[str, list[str]]] = [
    ("suicide", ["feel better", "got help", "i'm ok", "doing well", "i am fine", "therapy"]),
    ("suicidal", ["feel better", "got help", "i'm ok", "doing well", "i am fine"]),
    ("self harm", ["stopped", "recovered", "doing better", "in therapy"]),
    ("depressed", ["feel better", "feeling better", "improved", "therapy helping"]),
]

# ---------------------------------------------------------------------------
# Dual-purpose LLM prompt
# ---------------------------------------------------------------------------
# One LLM call per turn handles BOTH fact extraction AND safety classification.
# This catches implicit threats and nuanced violations that keyword matching
# cannot detect.
#
# IMPORTANT:
# This is NOT the roleplay runtime moderation layer.
# It is only for severe global safety memory that should persist across sessions.
# ---------------------------------------------------------------------------
_EXTRACTION_SYSTEM = """You are a memory and safety classifier for a chat application.
Analyse the user message and return ONLY a JSON object with this exact shape
(no markdown, no extra keys):
{
  "safety_violations": [
    {"category": "", "summary": ""}
  ],
  "facts": [
    {"text": "", "owner": "user", "scope": "user_private", "temporal_tag": "current", "importance": 1.0}
  ],
  "resolution_signals": [""]
}

SAFETY CLASSIFICATION RULES (safety_violations list):
Populate this list ONLY for severe, durable, cross-session safety risks that
should affect future chats globally.

Include ONLY these categories:
- violence_planning:
  * Intent or desire to harm, kill, or seriously injure another person
  * Violent threats
  * Planning an attack, shooting, bombing, murder, or weapon-based harm
- self_harm:
  * Self-harm or suicidal ideation
  * Desire or intent to kill oneself or seriously hurt oneself
- csam:
  * Sexual content involving minors
  * CSAM / child sexual abuse material
  * Underage sexual abuse or sexual interest in minors

IMPORTANT EXCLUSIONS:
- Consensual adult sexual content is NOT a safety violation.
  Examples: flirting, sexting, "I want to fuck you", consensual BDSM,
  adult sex work, rough/taboo adult fiction.
- Adult fictional taboo roleplay that may be hard-blocked elsewhere
  (e.g. incest, bestiality, fictional non-consent) is NOT a global
  safety violation in this classifier unless it explicitly involves:
  * minors in sexual context
  * real-world violence planning
  * self-harm / suicide intent
- Do NOT classify generic NSFW/adult sexual language as csam.
- Do NOT classify "teen", "young", "schoolgirl", "schoolboy", "barely legal",
  etc. as csam unless the message is clearly sexual.

Each entry:
- category is one of [violence_planning, self_harm, csam]
- summary is a short factual description

Leave safety_violations as [] if no GLOBAL safety violation is present.

FACT EXTRACTION RULES (facts list):
- Extract ONLY objective, useful personal facts about the USER.
- NEVER store:
  * Denials or self-assessments about rule compliance
  * Meta-commentary about the conversation or the AI system
  * The assistant's statements or character descriptions
  * Greetings, filler, or content with no durable personal meaning
- owner is always "user".
- use "user_private" for everything else.
- temporal_tag: "current" = true now, "historical" = past, "resolved" = no longer true.
- importance: 1.0 default, 2.0 for emotional distress, 3.0 for crisis or safety signals.
- Return empty list [] if nothing is worth storing.

RESOLUTION SIGNALS (resolution_signals list):
- List plain keywords (e.g. "suicide") that the user explicitly says are now resolved.
- Return empty list [] if none.
"""

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
    Extract facts and safety signals from *user_message*, then persist to DB.

    Pipeline:
    1. Keyword pre-screen — zero-token, catches explicit global safety phrases.
    2. LLM dual pass — catches implicit global risks + extracts facts.
    3. Resolution handling — marks stale facts resolved.
    4. Fact persistence — embeds and stores new facts.

    Returns a list of inserted memory_fact_ids.
    No-op (returns []) when DATABASE_URL is not set.
    All errors are caught and logged; this function never raises.
    """
    if not os.environ.get("DATABASE_URL"):
        return []

    inserted_ids: list[int] = []

    # Step 1 — Keyword pre-screen (zero extra LLM tokens).
    _handle_keyword_safety(user_message, user_id, conversation_id)

    # Step 2 — Resolution signals via keywords (also zero tokens).
    _handle_resolution_signals(user_message, user_id)

    # Step 3 — LLM dual pass: implicit safety + fact extraction.
    raw = _call_extraction_llm(user_message, llm_client, model)
    if raw is None:
        return inserted_ids

    # Step 4 — Persist LLM-detected safety violations not caught by keywords.
    for violation in raw.get("safety_violations", []):
        category = (violation.get("category") or "").strip()
        summary = (violation.get("summary") or "").strip()

        if not category or not summary:
            continue

        if category not in {"violence_planning", "self_harm", "csam"}:
            log.warning("extractor: ignored unknown safety category '%s'", category)
            continue

        # Guard against false-positive csam labels on generic adult NSFW.
        if category == "csam" and not _message_indicates_csam(user_message):
            log.warning(
                "extractor: ignored LLM csam classification for user %s "
                "(message lacked clear minor+sexual content): %s",
                user_id,
                summary,
            )
            continue

        _write_safety_flag(category, summary, user_id, conversation_id)

    # Step 5 — Process LLM-identified resolution signals.
    for keyword in raw.get("resolution_signals", []):
        if keyword and isinstance(keyword, str):
            count = db.resolve_facts_by_keyword(user_id, keyword.strip())
            log.debug("extractor: resolved %d facts for keyword '%s'", count, keyword)

    # Step 6 — Persist new personal facts.
    for fact in raw.get("facts", []):
        text = (fact.get("text") or "").strip()
        if not text:
            continue

        owner = fact.get("owner", "user")
        scope = fact.get("scope", "user_private")
        temporal = fact.get("temporal_tag", "current")
        importance = float(fact.get("importance", 1.0))

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
def _handle_keyword_safety(
    message: str,
    user_id: str,
    conversation_id: Optional[str],
) -> None:
    """
    Keyword-scan the message and write safety_global facts for any matches.

    Runs BEFORE the LLM call so safety flags are written even if the
    LLM extraction call subsequently fails.

    Deduplication is intentionally skipped here: duplicate safety flags are
    far less harmful than a missed one.
    """
    lower = message.lower()

    for category, keywords in SAFETY_KEYWORDS.items():
        if not any(kw in lower for kw in keywords):
            continue

        if category == "csam":
            if not _message_indicates_csam(message):
                continue

        summary = f"User expressed safety concern: {category}"
        _write_safety_flag(category, summary, user_id, conversation_id)


def _message_indicates_csam(message: str) -> bool:
    """
    Conservative check for minor-related sexual content.

    Requirements:
    - some minor/underage indicator must be present
    - and some sexual-context indicator must be present

    This prevents false positives like:
    - "I want to fuck you"  -> adult NSFW, not csam
    - "teen developer"      -> not sexual
    - "schoolboy error"     -> not sexual
    """
    lower = message.lower()

    minor_indicators = [
        "child porn",
        "csam",
        "underage sex",
        "underage",
        "minor",
        "young",
        "teen",
        "17",
        "schoolgirl",
        "schoolboy",
        "barely legal",
        "still developing",
        "perky young",
        "little girl",
        "little boy",
        "baby"  # only meaningful with sexual context
    ]

    has_minor_indicator = any(term in lower for term in minor_indicators)
    has_sexual_context = any(term in lower for term in CSAM_SEXUAL_CONTEXT_KEYWORDS)

    return has_minor_indicator and has_sexual_context


def _write_safety_flag(
    category: str,
    summary: str,
    user_id: str,
    conversation_id: Optional[str],
) -> None:
    """
    Persist a single safety_global fact to the DB.

    Safety facts:
    - scope='safety_global' — injected in every future session regardless
      of which character the user talks to.
    - decay_rate=0.0 — never auto-expire.
    - importance_score=10.0 — always surfaces at the top of the memory block.
    """
    embedding = embeddings.encode(summary)
    try:
        db.insert_fact(
            user_id=user_id,
            fact_text=summary,
            fact_owner="system",
            scope="safety_global",
            temporal_tag="current",
            character_id=None,
            confidence_score=1.0,
            importance_score=10.0,
            decay_rate=0.0,
            trigger_tags=[category],
            conversation_id=conversation_id,
            embedding=embedding,
        )
        log.warning(
            "extractor: safety flag written [%s] for user %s: %s",
            category,
            user_id,
            summary,
        )
    except Exception as exc:
        log.error("extractor: failed to write safety flag: %s", exc)


def _handle_resolution_signals(message: str, user_id: str) -> None:
    """
    Keyword-based resolution: if the user indicates a past issue is resolved
    (e.g. "I feel better now"), mark related non-safety facts as resolved
    before the LLM extraction runs.
    """
    lower = message.lower()

    for keyword, signals in RESOLUTION_SIGNALS:
        if any(sig in lower for sig in signals):
            count = db.resolve_facts_by_keyword(user_id, keyword)
            if count:
                log.info(
                    "extractor: resolved %d '%s' facts via resolution signal",
                    count,
                    keyword,
                )


def _call_extraction_llm(
    user_message: str,
    client: OpenAI,
    model: str,
) -> Optional[dict]:
    """
    Call the LLM with the dual-purpose prompt and return the parsed JSON dict.
    Returns None on any error so the caller can degrade gracefully.
    """
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": _EXTRACTION_SYSTEM},
                {"role": "user", "content": user_message},
            ],
            max_tokens=400,
            extra_body={"chat_template_kwargs": {"enable_thinking": False}},
        )

        raw_text = response.choices[0].message.content or ""
        raw_text = raw_text.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
        return json.loads(raw_text)

    except json.JSONDecodeError as exc:
        log.warning("extractor: LLM returned invalid JSON — %s", exc)
        return None
    except Exception as exc:
        log.warning("extractor: LLM extraction call failed — %s", exc)
        return None
