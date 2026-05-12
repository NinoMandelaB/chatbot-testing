"""
memory/extractor.py — compact fact extraction + global safety memory.

Stores only durable cross-session safety risks:
- violence_planning
- self_harm
- csam
- human_trafficking
- gender_violence

Context used for classification:
- current user message
- last 3 user messages from this conversation
- current-conversation memory facts
- current conversation summary

Important:
- This module is for durable memory, not runtime roleplay moderation.
- Adult consensual sexual content must NOT become safety_global.
- Adult taboo fiction must NOT become safety_global unless it clearly matches
  one of the allowed global categories.
- English + Kiswahili are optimized; other languages should still work via LLM.
"""

import json
import logging
import os
from typing import Any, Optional

from openai import OpenAI

from memory import db, embeddings

log = logging.getLogger(__name__)

MAX_CONTEXT_CHARS = 2400
MAX_SUMMARY_CHARS = 600
MAX_FACTS = 8
MAX_FACT_CHARS = 80
HISTORY_TURNS = 3

SAFETY_CATEGORIES = {
    "violence_planning",
    "self_harm",
    "csam",
    "human_trafficking",
    "gender_violence",
}

# ---------------------------------------------------------------------------
# Compact multilingual trigger sets
# ---------------------------------------------------------------------------
SAFETY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "self_harm": (
        "suicide", "suicidal", "kill myself", "end my life", "self harm",
        "self-harm", "hurt myself", "cutting myself", "overdose",
        "don't want to live", "nataka kujiua", "nitajiua", "kujiua",
        "sitaki kuishi", "najiumiza", "kujidhuru", "nimechoka kuishi",
    ),
    "violence_planning": (
        "attack plan", "kill plan", "how to kill", "i will kill",
        "i want to kill", "want to kill", "going to kill", "gonna kill",
        "planning to kill", "i'll kill", "murder", "bomb", "shoot",
        "school shooting", "mass shooting", "nataka kuua", "nitamuua",
        "nitaua", "kuua mtu", "mpango wa kushambulia", "mauaji",
        "bomu", "bunduki", "silaha",
    ),
    "csam": (
        "child porn", "csam", "underage sex", "underage", "minor sexual",
        "schoolgirl", "schoolboy", "barely legal", "teen", "young girl",
        "young boy", "little girl", "little boy", "17", "16", "15",
        "14", "13", "12", "11", "10", "mtoto", "mdogo", "chini ya miaka",
        "msichana mdogo", "mvulana mdogo", "binti mdogo", "kijana mdogo",
    ),
    "human_trafficking": (
        "traffic her", "traffic him", "sell her", "sell him", "sell the girl",
        "pimp her", "pimp him", "share her", "share him", "pass her around",
        "sex slave", "forced prostitution", "escort her for money",
        "bring girls for men", "deliver girls", "brothel", "buy a girl",
        "human trafficking", "trafficking", "msafirishe", "uuze msichana",
        "kuuza mtoto", "kumsafirisha kwa wanaume", "umalaya wa kulazimishwa",
        "mtumwa wa ngono", "kumpitisha kwa wanaume",
    ),
    "gender_violence": (
        "fgm", "female genital mutilation", "cut her", "cut the girl",
        "honour killing", "honor killing", "forced marriage", "marry her off",
        "rape her", "beat your wife", "beat my wife", "domestic violence",
        "intimate partner violence", "acid attack", "ukeketaji", "kumkeketa",
        "mkate msichana", "ndoa ya lazima", "olewa kwa lazima",
        "ubakaji", "mpige mke", "ukatili wa kijinsia",
        "cut my clit", "cut her clit", "cut off clit",
        "female circumcision", "circumcise her", "circumcise me",
        "clitoris removed", "clitoris cut", "kata uke wangu",
        "kata clitoris", "tohara ya msichana", "kukatwa sehemu",
        "ukeketaji wangu",
    ),
}

MINOR_HINTS: tuple[str, ...] = (
    "child", "minor", "underage", "teen", "young girl", "young boy",
    "little girl", "little boy", "schoolgirl", "schoolboy",
    "barely legal", "17", "16", "15", "14", "13", "12", "11", "10",
    "mtoto", "mdogo", "chini ya miaka", "msichana mdogo",
    "mvulana mdogo", "binti mdogo", "kijana mdogo",
)

SEXUAL_HINTS: tuple[str, ...] = (
    "sex", "sexy", "nude", "naked", "fuck", "fucking", "horny",
    "cum", "rape", "molest", "blowjob", "bj", "anal", "oral",
    "penetrat", "porn", "nsfw", "slut", "spread your legs", "touch me",
    "ngono", "uchi", "mtupu", "tupu", "tamaa", "kubaka", "kunyonya",
    "mboo", "kuma", "mbegu", "pornografia",
)

TRAFFICKING_HINTS: tuple[str, ...] = (
    "sell", "buy", "price", "for money", "for men", "brothel", "client",
    "customers", "pimp", "traffic", "share her", "share him", "pass her around",
    "pass him around", "deliver girls", "deliver boys", "sex slave",
    "forced prostitution", "owned by men", "given to men", "uuze", "nunua",
    "bei", "wateja", "dalali", "msafirishe", "mtumwa wa ngono",
    "kumpitisha kwa wanaume", "wanaume wengi",
)

GENDER_VIOLENCE_HINTS: tuple[str, ...] = (
    "fgm", "female genital mutilation", "cut her", "cut the girl",
    "honour killing", "honor killing", "forced marriage", "marry her off",
    "rape her", "beat your wife", "beat my wife", "domestic violence",
    "intimate partner violence", "acid attack", "ukeketaji", "kumkeketa",
    "mkate msichana", "ndoa ya lazima", "olewa kwa lazima",
    "ubakaji", "mpige mke", "ukatili wa kijinsia",
    "cut my clit", "cut her clit", "cut off clit",
    "female circumcision", "circumcise her", "circumcise me",
    "clitoris removed", "clitoris cut", "kata uke wangu",
    "kata clitoris", "tohara ya msichana", "kukatwa sehemu",
    "ukeketaji wangu",
)

VIOLENCE_INTENT_HINTS: tuple[str, ...] = (
    "i want to kill", "want to kill", "i will kill", "i'll kill",
    "going to kill", "gonna kill", "kill him", "kill her", "kill them",
    "attack plan", "kill plan", "how to kill", "murder", "shoot him",
    "shoot her", "bomb", "nataka kuua", "nitamuua", "nitaua",
    "kuua mtu", "mpango wa kushambulia", "mauaji",
)

RESOLUTION_SIGNALS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "suicide",
        (
            "feel better", "got help", "i'm ok", "doing well", "i am fine",
            "therapy", "najisikia vizuri", "nimepata msaada",
            "niko sawa", "naendelea vizuri",
        ),
    ),
    (
        "suicidal",
        (
            "feel better", "got help", "i'm ok", "doing well", "i am fine",
            "najisikia vizuri", "niko sawa",
        ),
    ),
    (
        "self harm",
        (
            "stopped", "recovered", "doing better", "in therapy",
            "nimeacha", "nimepona", "naendelea vizuri",
        ),
    ),
    (
        "depressed",
        (
            "feel better", "feeling better", "improved", "therapy helping",
            "najisikia vizuri", "nafuu", "imeimarika",
        ),
    ),
)

_EXTRACTION_SYSTEM = """Return JSON only:
{"global_safety":[{"category":"","summary":""}],"facts":[{"text":"","owner":"user","scope":"user_private","temporal_tag":"current","importance":1.0}],"resolution_signals":[""]}

Rules:
- global_safety = only durable cross-session risks, never normal facts.
- Allowed categories: violence_planning, self_harm, csam, human_trafficking, gender_violence.
- Use provided context: current message, recent user messages, conversation facts, conversation summary.
- csam = sexual content involving minors.
- human_trafficking = sale, transfer, pimping, coercive sharing, sexual exploitation, forced prostitution.
- gender_violence = FGM, forced marriage, rape, partner violence, honor killing, similar abuse.
- Ignore consensual adult sexual content.
- Ignore adult taboo roleplay unless it clearly matches an allowed category.
- Never put safety items into facts.

- facts = only stable, durable user information:
  * identity or biography
  * lasting preferences
  * ongoing life situation
  * long-term relationships
  * durable goals, plans, or responsibilities
  * relationship between user and character / assistant
- Broad recurring preferences may be stored, 
- Do NOT store:
  * explicit scene content, erotic instructions, fetish detail, or fantasy scripts
  * one-off roleplay scenarios or quoted sexual lines
  * one-off requests, momentary chat actions, or temporary conversational details
  * moderation events, refusals, blocked content, or safety labels
  * assistant text, paraphrases of the chat, or meta commentary
- If unsure whether something is durable, omit it.
- owner="user", scope="user_private", temporal_tag=current|historical|resolved.
- importance: 1.0 default, 2.0 distress, 3.0 crisis.
- resolution_signals: plain resolved keywords only.
- Use [] when empty.
"""


def extract_and_store(
    user_message: str,
    user_id: str,
    character_id: Optional[str],
    conversation_id: Optional[str],
    llm_client: OpenAI,
    model: str,
) -> list[int]:
    """
    Extract durable personal facts and global safety risks from current message
    plus compact same-conversation context.
    """
    if not os.environ.get("DATABASE_URL"):
        return []

    inserted_ids: list[int] = []
    ctx = _build_context(user_message, user_id, conversation_id)
    scan_text = ctx["scan_text"]

    _handle_keyword_safety(scan_text, user_id, conversation_id)
    _handle_resolution_signals(scan_text, user_id)

    raw = _call_extraction_llm(ctx["llm_input"], llm_client, model)
    if raw is None:
        return inserted_ids

    for violation in raw.get("global_safety", []):
        category = (violation.get("category") or "").strip()
        summary = (violation.get("summary") or "").strip()

        if not category or not summary or category not in SAFETY_CATEGORIES:
            continue
        if not _valid_safety_hit(category, scan_text):
            log.warning(
                "extractor: ignored weak %s classification for user %s: %s",
                category, user_id, summary,
            )
            continue
        _write_safety_flag(category, summary, user_id, conversation_id)

    for keyword in raw.get("resolution_signals", []):
        if isinstance(keyword, str) and keyword.strip():
            db.resolve_facts_by_keyword(user_id, keyword.strip())

    for fact in raw.get("facts", []):
        text = (fact.get("text") or "").strip()
        if not text or _should_skip_fact(text):
            continue

        temporal = fact.get("temporal_tag", "current")
        fact_id = db.insert_fact(
            user_id=user_id,
            fact_text=text,
            fact_owner=fact.get("owner", "user"),
            scope=fact.get("scope", "user_private"),
            temporal_tag=temporal,
            character_id=character_id,
            confidence_score=1.0,
            importance_score=float(fact.get("importance", 1.0)),
            decay_rate=0.005 if temporal == "current" else 0.02,
            conversation_id=conversation_id,
            embedding=embeddings.encode(text),
        )
        inserted_ids.append(fact_id)

    return inserted_ids


def _build_context(
    user_message: str,
    user_id: str,
    conversation_id: Optional[str],
) -> dict[str, str]:
    """
    Build compact context from:
    - current user message
    - last 3 user messages in this conversation
    - same-conversation memory facts
    - conversation summary

    Returns:
    - scan_text: concatenated plain text for keyword guards
    - llm_input: compact structured text for the model
    """
    history = _get_recent_user_messages(user_id, conversation_id, limit=HISTORY_TURNS)
    facts = _get_conversation_facts(user_id, conversation_id, limit=MAX_FACTS)
    summary = _get_conversation_summary(user_id, conversation_id)

    history_block = "\n".join(f"- {m}" for m in history if m)
    facts_block = "\n".join(f"- {f}" for f in facts if f)

    summary = _clip(summary, MAX_SUMMARY_CHARS)

    llm_parts = [
        f"CURRENT USER MESSAGE:\n{_clip(user_message, 700)}",
    ]
    if history_block:
        llm_parts.append(f"LAST {HISTORY_TURNS} USER MESSAGES:\n{history_block}")
    if facts_block:
        llm_parts.append(f"CURRENT CONVERSATION FACTS:\n{facts_block}")
    if summary:
        llm_parts.append(f"CONVERSATION SUMMARY:\n{summary}")

    llm_input = "\n\n".join(llm_parts)
    llm_input = _clip(llm_input, MAX_CONTEXT_CHARS)

    scan_parts = [user_message]
    scan_parts.extend(history)
    scan_parts.extend(facts)
    if summary:
        scan_parts.append(summary)
    scan_text = "\n".join(x for x in scan_parts if x)
    scan_text = _clip(scan_text, MAX_CONTEXT_CHARS)

    return {"scan_text": scan_text, "llm_input": llm_input}


def _get_recent_user_messages(
    user_id: str,
    conversation_id: Optional[str],
    limit: int = 3,
) -> list[str]:
    """
    Best-effort fetch of recent user messages for this conversation.
    Falls back cleanly if the DB helper does not exist.
    """
    if not conversation_id:
        return []

    candidates = (
        "get_recent_user_messages",
        "get_recent_messages",
        "get_conversation_messages",
    )

    for name in candidates:
        fn = getattr(db, name, None)
        if not callable(fn):
            continue
        try:
            rows = fn(user_id=user_id, conversation_id=conversation_id, limit=limit + 1)
            return _extract_user_message_texts(rows, limit=limit, current_message=None)
        except Exception as exc:
            log.debug("extractor: %s unavailable/failed: %s", name, exc)

    return []


def _get_conversation_facts(
    user_id: str,
    conversation_id: Optional[str],
    limit: int = 8,
) -> list[str]:
    """
    Best-effort fetch of same-conversation memory facts.
    Only keeps compact fact_text strings.
    """
    if not conversation_id:
        return []

    candidates = (
        "get_facts_for_conversation",
        "get_conversation_facts",
        "get_memory_facts",
    )

    for name in candidates:
        fn = getattr(db, name, None)
        if not callable(fn):
            continue
        try:
            rows = fn(user_id=user_id, conversation_id=conversation_id, limit=limit)
            out: list[str] = []
            for row in rows or []:
                text = _row_get(row, "fact_text")
                if text and not _should_skip_fact(text):
                    out.append(_clip(text, MAX_FACT_CHARS))
            return out[:limit]
        except Exception as exc:
            log.debug("extractor: %s unavailable/failed: %s", name, exc)

    return []


def _get_conversation_summary(user_id: str, conversation_id: Optional[str]) -> str:
    """
    Best-effort fetch of same-conversation summary.
    """
    if not conversation_id:
        return ""

    candidates = (
        "get_conversation_summary",
        "get_summary_for_conversation",
        "get_latest_summary",
    )

    for name in candidates:
        fn = getattr(db, name, None)
        if not callable(fn):
            continue
        try:
            row = fn(user_id=user_id, conversation_id=conversation_id)
            if isinstance(row, str):
                return row
            return (
                _row_get(row, "summary")
                or _row_get(row, "summary_text")
                or _row_get(row, "content")
                or ""
            )
        except Exception as exc:
            log.debug("extractor: %s unavailable/failed: %s", name, exc)

    return ""


def _extract_user_message_texts(
    rows: Any,
    limit: int,
    current_message: Optional[str],
) -> list[str]:
    out: list[str] = []

    for row in rows or []:
        role = (_row_get(row, "role") or _row_get(row, "sender") or "").lower()
        text = (
            _row_get(row, "message_text")
            or _row_get(row, "content")
            or _row_get(row, "text")
            or ""
        )
        if not text:
            continue
        if role and role != "user":
            continue
        if current_message and text.strip() == current_message.strip():
            continue
        out.append(_clip(text, 240))

    return out[-limit:]


def _row_get(row: Any, key: str) -> Any:
    if isinstance(row, dict):
        return row.get(key)
    return getattr(row, key, None)


def _clip(text: str, limit: int) -> str:
    text = (text or "").strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _handle_keyword_safety(
    message: str,
    user_id: str,
    conversation_id: Optional[str],
) -> None:
    lower = message.lower()

    for category, keywords in SAFETY_KEYWORDS.items():
        if not any(k in lower for k in keywords):
            continue
        if not _valid_safety_hit(category, lower):
            continue
        _write_safety_flag(
            category,
            f"User expressed safety concern: {category}",
            user_id,
            conversation_id,
        )


def _valid_safety_hit(category: str, message: str) -> bool:
    lower = message.lower()

    if category == "csam":
        return _message_indicates_csam(lower)
    if category == "violence_planning":
        return any(k in lower for k in VIOLENCE_INTENT_HINTS)
    if category == "self_harm":
        return any(k in lower for k in SAFETY_KEYWORDS["self_harm"])
    if category == "human_trafficking":
        return any(k in lower for k in TRAFFICKING_HINTS)
    if category == "gender_violence":
        return any(k in lower for k in GENDER_VIOLENCE_HINTS)

    return False


def _message_indicates_csam(message: str) -> bool:
    lower = message.lower()
    return any(k in lower for k in MINOR_HINTS) and any(k in lower for k in SEXUAL_HINTS)


def _should_skip_fact(text: str) -> bool:
    lower = text.lower().strip()
    return (
        not lower
        or lower.startswith("user said ")
        or lower.startswith("assistant said ")
        or lower.startswith("the assistant ")
        or lower.startswith("roleplay:")
        or lower.startswith("scene:")
        or len(lower) < 8
    )


def _write_safety_flag(
    category: str,
    summary: str,
    user_id: str,
    conversation_id: Optional[str],
) -> None:
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
            embedding=embeddings.encode(summary),
        )
        log.warning(
            "extractor: safety flag written [%s] for user %s: %s",
            category, user_id, summary,
        )
    except Exception as exc:
        log.error("extractor: failed to write safety flag: %s", exc)


def _handle_resolution_signals(message: str, user_id: str) -> None:
    lower = message.lower()
    for keyword, signals in RESOLUTION_SIGNALS:
        if any(sig in lower for sig in signals):
            db.resolve_facts_by_keyword(user_id, keyword)


def _call_extraction_llm(context_text: str, client: OpenAI, model: str) -> Optional[dict]:
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": _EXTRACTION_SYSTEM},
                {"role": "user", "content": context_text},
            ],
            max_tokens=320,
            extra_body={"chat_template_kwargs": {"enable_thinking": False}},
        )
        raw_text = (response.choices[0].message.content or "").strip()
        raw_text = (
            raw_text
            .removeprefix("```json")
            .removeprefix("```")
            .removesuffix("```")
            .strip()
        )
        return json.loads(raw_text)
    except Exception as exc:
        log.warning("extractor: LLM extraction failed — %s", exc)
        return None
