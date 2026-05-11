"""
memory/summariser.py  —  Conversation summarisation for hybrid memory.

After every SUMMARISE_EVERY turns the /chat endpoint calls maybe_summarise().
This module:
  1. Builds a compact prompt from the recent conversation history.
  2. Calls the LLM to compress it into a single paragraph (~150 words).
  3. Deactivates the previous summary for this (user_id, character_id) pair.
  4. Writes the new summary to conversation_summaries via memory/db.py.

The summary is later prepended to the [MEMORY] block by memory/retriever.py,
giving the LLM long-term context without consuming many tokens.

Token budget: one LLM call per SUMMARISE_EVERY turns; the call uses ~300
prompt tokens and returns ~150 tokens.  Skipped entirely when DATABASE_URL
or CORTECS_API_KEY is not configured.
"""

import logging
import os
from typing import Optional

from openai import OpenAI

from memory import db

log = logging.getLogger(__name__)

# Summarise after this many new turns (user + assistant counts as 1 turn).
SUMMARISE_EVERY: int = 6

# Model used for summarisation.  Intentionally a small, fast model.
_SUMMARY_MODEL: str = os.environ.get("CORTECS_SUMMARY_MODEL", "qwen3.5-9b")

# System prompt that instructs the model to produce a terse summary.
_SYSTEM_PROMPT = (
    "You are a memory compression assistant. "
    "Given a conversation excerpt, write a single dense paragraph (max 150 words) "
    "that captures the key facts, tone, and context. "
    "Write in third person (e.g. 'The user mentioned...'). "
    "Do NOT include greetings, filler, or the word 'summary'. "
    "Return ONLY the paragraph, no markdown."
)


def maybe_summarise(
    user_id: str,
    character_id: str,
    history: list[dict],
    api_key: str,
    base_url: str,
) -> None:
    """
    Trigger a summary update if the conversation has grown long enough.

    Parameters
    ----------
    user_id      : identifies the end user.
    character_id : identifies the AI character / persona.
    history      : list of {role, content} dicts (the full conversation so far).
    api_key      : Cortecs API key (forwarded from app config).
    base_url     : Cortecs base URL.

    This function is intentionally fire-and-forget: any error is logged but
    never re-raised, so it never blocks the main chat response.
    """
    # Skip if DB or API are not configured.
    if not os.environ.get("DATABASE_URL") or not api_key:
        return

    # Only session-aware requests can be summarised.
    if not user_id or not character_id:
        return

    # Count actual user turns in the history.
    user_turns = sum(1 for m in history if m.get("role") == "user")
    if user_turns < SUMMARISE_EVERY:
        return

    try:
        _run_summarise(user_id, character_id, history, api_key, base_url)
    except Exception as exc:
        log.error("summariser.maybe_summarise failed: %s", exc)


# ---------------------------------------------------------------------------
# Internal logic
# ---------------------------------------------------------------------------

def _run_summarise(
    user_id: str,
    character_id: str,
    history: list[dict],
    api_key: str,
    base_url: str,
) -> None:
    """Build the LLM prompt, call the API, and persist the result."""
    # Take the most recent 20 messages to keep the prompt compact.
    recent = history[-20:]
    turn_count = sum(1 for m in recent if m.get("role") == "user")

    # Format conversation as plain text for the LLM.
    conversation_text = _format_history(recent)

    # Call the LLM.
    client = OpenAI(api_key=api_key, base_url=base_url)
    response = client.chat.completions.create(
        model=_SUMMARY_MODEL,
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": f"Conversation to summarise:\n\n{conversation_text}"},
        ],
        max_tokens=200,
        stream=False,
        extra_body={"chat_template_kwargs": {"enable_thinking": False}},
    )

    summary_text = ""
    if response.choices:
        msg = response.choices[0].message
        summary_text = (getattr(msg, "content", "") or "").strip()

    if not summary_text:
        log.warning("summariser: LLM returned empty summary for user=%s char=%s", user_id, character_id)
        return

    # Persist: deactivate the old summary, then insert the new one.
    db.upsert_summary(user_id, character_id, summary_text, turn_count)
    log.info(
        "summariser: updated summary for user=%s char=%s (%d turns)",
        user_id, character_id, turn_count,
    )


def _format_history(messages: list[dict]) -> str:
    """Convert a list of {role, content} dicts to readable plain text."""
    lines = []
    for m in messages:
        role = m.get("role", "unknown").capitalize()
        content = (m.get("content") or "").strip()
        if content:  # skip empty messages (e.g. safety sandwich injections)
            lines.append(f"{role}: {content}")
    return "\n".join(lines)
