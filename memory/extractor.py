"""
memory/extractor.py — compact fact extraction + global safety memory.

Stores only durable cross-session risks:
- violence_planning
- self_harm
- csam

Per-chat erotic / roleplay hard-blocks are handled elsewhere and should not
be written to safety_global unless they indicate one of the categories above.
"""

import json
import logging
import os
from typing import Optional

from openai import OpenAI

from memory import db, embeddings

log = logging.getLogger(__name__)

# Compact multilingual trigger sets for zero-token pre-screening.
SAFETY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "self_harm": (
        "suicide", "suicidal", "kill myself", "end my life", "self harm",
        "self-harm", "hurt myself", "cutting myself", "overdose",
        "don't want to live", "nataka kujiua", "nitajiua", "kujiua",
        "sitaki kuishi", "najiumiza", "kujidhuru", "nimechoka kuishi",
    ),
    "violence_planning": (
        "school shooting", "mass shooting", "attack plan", "kill plan",
        "how to kill", "i will kill", "i want to kill", "want to kill",
        "going to kill", "gonna kill", "planning to kill", "i'll kill",
        "murder someone", "i want to murder", "bomb", "weapon",
        "nataka kuua", "nitamuua", "nitaua", "kuua mtu", "mpango wa kushambulia",
        "shambulio", "bomu", "bunduki", "silaha", "mauaji",
    ),
    "csam": (
        "child porn", "csam", "underage sex", "underage", "minor sexual",
        "schoolgirl", "schoolboy", "barely legal", "still developing",
        "perky young", "teen", "mtoto", "mdogo", "chini ya miaka",
        "msichana mdogo", "mvulana mdogo", "binti mdogo", "kijana mdogo",
    ),
}

MINOR_HINTS: tuple[str, ...] = (
    "child porn", "csam", "underage sex", "underage", "minor", "young",
    "teen", "17", "schoolgirl", "schoolboy", "barely legal",
    "still developing", "perky young", "little girl", "little boy",
    "mtoto", "mdogo", "chini ya miaka", "msichana mdogo",
    "mvulana mdogo", "binti mdogo", "kijana mdogo",
)

SEXUAL_HINTS: tuple[str, ...] = (
    "sex", "sexy", "nude", "naked", "fuck", "fucking", "horny",
    "turned on", "cum", "rape", "molest", "blowjob", "bj", "anal",
    "oral", "penetrat", "porn", "nsfw",
    "ngono", "uchi", "mtupu", "tupu", "tamaa", "kubaka", "kunyonya",
    "mboo", "kuma", "mbegu", "pornografia",
)

RESOLUTION_SIGNALS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("suicide", ("feel better", "got help", "i'm ok", "doing well", "i am fine", "therapy",
                 "najisikia vizuri", "nimepata msaada", "niko sawa", "naendelea vizuri", "nina therapy")),
    ("suicidal", ("feel better", "got help", "i'm ok", "doing well", "i am fine",
                  "najisikia vizuri", "niko sawa")),
    ("self harm", ("stopped", "recovered", "doing better", "in therapy",
                   "nimeacha", "nimepona", "naendelea vizuri", "kwenye therapy")),
    ("depressed", ("feel better", "feeling better", "improved", "therapy helping",
                   "najisikia vizuri", "nafuu", "imeimarika")),
)

_EXTRACTION_SYSTEM = """Return JSON only:
{"safety_violations":[{"category":"","summary":""}],"facts":[{"text":"","owner":"user","scope":"user_private","temporal_tag":"current","importance":1.0}],"resolution_signals":[""]}

Rules:
- safety_violations: only severe global risks for future chats.
- Categories only: violence_planning, self_harm, csam.
- violence_planning = intent/threat/plan to seriously harm others.
- self_harm = suicidal or self-harm intent.
- csam = sexual content involving minors only.
- Ignore consensual adult sexual content.
- Ignore adult fictional taboo roleplay unless it involves minors, real-world violence, or self-harm.
- Do not label generic NSFW as csam.
- facts: only durable user facts, not filler/meta/assistant text.
- owner="user", scope="user_private".
- temporal_tag: current|historical|resolved.
- importance: 1.0 default, 2.0 distress, 3.0 crisis.
- resolution_signals: plain keywords explicitly marked resolved.
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
    if not os.environ.get("DATABASE_URL"):
        return []

    inserted_ids: list[int] = []

    _handle_keyword_safety(user_message, user_id, conversation_id)
    _handle_resolution_signals(user_message, user_id)

    raw = _call_extraction_llm(user_message, llm_client, model)
    if raw is None:
        return inserted_ids

    for violation in raw.get("safety_violations", []):
        category = (violation.get("category") or "").strip()
        summary = (violation.get("summary") or "").strip()
        if not category or not summary or category not in {"violence_planning", "self_harm", "csam"}:
            continue
        if category == "csam" and not _message_indicates_csam(user_message):
            log.warning(
                "extractor: ignored false-positive csam for user %s: %s",
                user_id,
                summary,
            )
            continue
        _write_safety_flag(category, summary, user_id, conversation_id)

    for keyword in raw.get("resolution_signals", []):
        if isinstance(keyword, str) and keyword.strip():
            db.resolve_facts_by_keyword(user_id, keyword.strip())

    for fact in raw.get("facts", []):
        text = (fact.get("text") or "").strip()
        if not text:
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


def _handle_keyword_safety(message: str, user_id: str, conversation_id: Optional[str]) -> None:
    lower = message.lower()
    for category, keywords in SAFETY_KEYWORDS.items():
        if not any(k in lower for k in keywords):
            continue
        if category == "csam" and not _message_indicates_csam(lower):
            continue
        _write_safety_flag(category, f"User expressed safety concern: {category}", user_id, conversation_id)


def _message_indicates_csam(message: str) -> bool:
    lower = message.lower()
    return any(k in lower for k in MINOR_HINTS) and any(k in lower for k in SEXUAL_HINTS)


def _write_safety_flag(category: str, summary: str, user_id: str, conversation_id: Optional[str]) -> None:
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
        log.warning("extractor: safety flag written [%s] for user %s: %s", category, user_id, summary)
    except Exception as exc:
        log.error("extractor: failed to write safety flag: %s", exc)


def _handle_resolution_signals(message: str, user_id: str) -> None:
    lower = message.lower()
    for keyword, signals in RESOLUTION_SIGNALS:
        if any(sig in lower for sig in signals):
            db.resolve_facts_by_keyword(user_id, keyword)


def _call_extraction_llm(user_message: str, client: OpenAI, model: str) -> Optional[dict]:
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": _EXTRACTION_SYSTEM},
                {"role": "user", "content": user_message},
            ],
            max_tokens=300,
            extra_body={"chat_template_kwargs": {"enable_thinking": False}},
        )
        raw_text = (response.choices[0].message.content or "").strip()
        raw_text = raw_text.lstrip("```json").lstrip("```").rstrip("```").strip()
        return json.loads(raw_text)
    except Exception as exc:
        log.warning("extractor: LLM extraction failed — %s", exc)
        return None
