"""
memory/extractor.py — compact fact extraction + global safety memory.

Stores only durable cross-session safety risks:
- violence_planning
- self_harm
- csam
- human_trafficking
- gender_violence

Important:
- This module is for durable memory, not runtime roleplay moderation.
- Adult consensual sexual content must NOT become safety_global.
- Adult taboo fiction must NOT become safety_global unless it clearly contains
  one of the categories above.
- English + Kiswahili are optimized; other languages should still work via LLM.
"""

import json
import logging
import os
from typing import Optional

from openai import OpenAI

from memory import db, embeddings

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Compact multilingual trigger sets
# These are broad enough for pre-screening, but category-specific guards below
# decide whether a durable safety_global fact should actually be written.
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

# Minor/age markers. Used with sexual context for CSAM.
MINOR_HINTS: tuple[str, ...] = (
    "child", "minor", "underage", "teen", "young girl", "young boy",
    "little girl", "little boy", "schoolgirl", "schoolboy",
    "barely legal", "17", "16", "15", "14", "13", "12", "11", "10",
    "mtoto", "mdogo", "chini ya miaka", "msichana mdogo",
    "mvulana mdogo", "binti mdogo", "kijana mdogo",
)

# Sexual context. Keeps adult NSFW from turning into CSAM unless minors are present.
SEXUAL_HINTS: tuple[str, ...] = (
    "sex", "sexy", "nude", "naked", "fuck", "fucking", "horny",
    "cum", "rape", "molest", "blowjob", "bj", "anal", "oral",
    "penetrat", "porn", "nsfw", "slut", "spread your legs", "touch me",
    "ngono", "uchi", "mtupu", "tupu", "tamaa", "kubaka", "kunyonya",
    "mboo", "kuma", "mbegu", "pornografia",
)

# Control / sale / coercion indicators for trafficking.
TRAFFICKING_HINTS: tuple[str, ...] = (
    "sell", "buy", "price", "for money", "for men", "brothel", "client",
    "customers", "pimp", "traffic", "share her", "share him", "pass her around",
    "pass him around", "deliver girls", "deliver boys", "sex slave",
    "forced prostitution", "owned by men", "given to men", "uuze", "nunua",
    "bei", "wateja", "dalali", "msafirishe", "mtumwa wa ngono",
    "kumpitisha kwa wanaume", "wanaume wengi",
)

# Gender-based violence indicators.
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

# Violent intent indicators to avoid flagging generic mentions of weapons.
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

# Compact prompt for low token usage.
_EXTRACTION_SYSTEM = """Return JSON only:
{"global_safety":[{"category":"","summary":""}],"facts":[{"text":"","owner":"user","scope":"user_private","temporal_tag":"current","importance":1.0}],"resolution_signals":[""]}

Rules:
- global_safety = only durable cross-session risks, never normal facts.
- Allowed global_safety categories: violence_planning, self_harm, csam, human_trafficking, gender_violence.
- violence_planning: threat, intent, or plan to seriously harm others.
- self_harm: suicidal or self-harm intent.
- csam: sexual content involving minors.
- human_trafficking: sale, transfer, pimping, coercive sharing, sexual exploitation, forced prostitution.
- gender_violence: FGM, forced marriage, rape, partner violence, honor killing, similar abuse.
- Ignore consensual adult sexual content.
- Ignore adult taboo roleplay unless it clearly matches an allowed global_safety category.
- Never put safety items into facts.
- facts = only durable user facts; no sexual roleplay details, no moderation details, no filler, no assistant text.
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
    Extract durable personal facts and global safety risks from user_message.

    Flow:
    1. Zero-token keyword pre-screen for explicit safety signals.
    2. Zero-token keyword resolution handling.
    3. Low-token LLM pass for implicit safety + durable fact extraction.
    4. Persist facts and safety flags.

    Returns inserted memory fact IDs.
    """
    if not os.environ.get("DATABASE_URL"):
        return []

    inserted_ids: list[int] = []

    _handle_keyword_safety(user_message, user_id, conversation_id)
    _handle_resolution_signals(user_message, user_id)

    raw = _call_extraction_llm(user_message, llm_client, model)
    if raw is None:
        return inserted_ids

    for violation in raw.get("global_safety", []):
        category = (violation.get("category") or "").strip()
        summary = (violation.get("summary") or "").strip()

        if not category or not summary:
            continue
        if category not in {
            "violence_planning",
            "self_harm",
            "csam",
            "human_trafficking",
            "gender_violence",
        }:
            continue
        if not _valid_safety_hit(category, user_message):
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


def _handle_keyword_safety(
    message: str,
    user_id: str,
    conversation_id: Optional[str],
) -> None:
    """
    Cheap pre-screen. Only writes safety_global if the category-specific guard
    confirms the hit is strong enough.
    """
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
    """
    Category-specific validation to reduce false positives while still catching
    real dangerous escalations in English and Kiswahili.
    """
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
    """
    Conservative CSAM check:
    - requires a minor/age marker
    - requires sexual context
    This catches cases like "he is just 17" after explicit sexual instructions,
    while avoiding generic adult NSFW -> csam false positives.
    """
    lower = message.lower()
    return any(k in lower for k in MINOR_HINTS) and any(k in lower for k in SEXUAL_HINTS)


def _should_skip_fact(text: str) -> bool:
    """
    Avoid storing sexual/roleplay scene details or moderation-adjacent junk
    as durable user facts.
    """
    lower = text.lower()

    blocked_fragments = (
        "sexual object",
        "fuck slut",
        "secret relationship",
        "shared with others",
        "spread legs",
        "touch me",
        "plaything",
        "be used by",
        "roleplay",
        "assistant",
        "greeted the assistant",
        "user is x years old",
    )
    return any(x in lower for x in blocked_fragments)


def _write_safety_flag(
    category: str,
    summary: str,
    user_id: str,
    conversation_id: Optional[str],
) -> None:
    """
    Persist a durable safety_global fact.
    """
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


def _call_extraction_llm(
    user_message: str,
    client: OpenAI,
    model: str,
) -> Optional[dict]:
    """
    Low-token structured extraction. Gracefully returns None on failure.
    """
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": _EXTRACTION_SYSTEM},
                {"role": "user", "content": user_message},
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
