"""
memory/summariser.py  —  Conversation summarisation for hybrid memory.

After every SUMMARISE_EVERY turns the /chat endpoint calls maybe_summarise().
This module:
  1. Builds a compact prompt from the recent conversation history.
  2. Calls the LLM (same model the user selected for chat) to compress the
     conversation into a single paragraph (~150 words).
  3. Deactivates the previous summary for this (user_id, character_id) pair.
  4. Writes the new summary to conversation_summaries via memory/db.py.

The summary is later prepended to the [MEMORY] block by memory/retriever.py,
giving the LLM long-term context without consuming many tokens.

Token budget: one LLM call per SUMMARISE_EVERY turns; the call uses ~300
prompt tokens and returns ~150 tokens.  Skipped entirely when DATABASE_URL
or the API key is not configured.

Turn counting
-------------
The frontend may send only a limited slice of recent chat history to control
prompt length. To ensure summarisation triggers at the correct interval
regardless of the frontend slice size, app.py passes the cumulative
turn_count already stored in the DB (prior_turn_count). The threshold is then
checked against the combined total, not just the slice.

Model selection
---------------
The model used for summarisation matches the model the user selected for chat
(passed in via the `model` parameter). If no model is provided, it falls back
to the CORTECS_SUMMARY_MODEL env var, or finally to DEFAULT_SUMMARY_MODEL.
"""
import logging
import os
from typing import Optional

from openai import OpenAI

from memory import db

log = logging.getLogger(__name__)

# How many NEW user turns must accumulate since the last summary before
# a new summary is generated. Compared against the delta since last summary,
# not the frontend history slice size.
SUMMARISE_EVERY: int = 6

# Fallback model when no model is passed in and the env var is not set.
DEFAULT_SUMMARY_MODEL: str = "qwen3.5-9b"

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
    model: Optional[str] = None,
    prior_turn_count: int = 0,
) -> None:
    """
    Trigger a summary update if enough NEW turns have accumulated.

    Parameters
    ----------
    user_id          : identifies the end user.
    character_id     : identifies the AI character / persona.
    history          : list of {role, content} dicts (the current history
                       slice from the frontend + the just-completed turn).
    api_key          : Cortecs API key.
    base_url         : Cortecs base URL.
    model            : LLM model name to use for summarisation.
    prior_turn_count : cumulative user-turn count stored in the last summary
                       row (0 if no summary exists yet). Fetched from DB by
                       app.py so this module stays decoupled from the DB
                       schema detail and the trigger works even when the
                       frontend only sends a partial history slice.

    Trigger logic
    -------------
    new_turns  = user turns in the current history slice
    total      = prior_turn_count + new_turns
    Trigger when total crosses the next multiple of SUMMARISE_EVERY above
    prior_turn_count, i.e. when new_turns >= (SUMMARISE_EVERY -
    prior_turn_count % SUMMARISE_EVERY).

    This function is intentionally fire-and-forget: any error is logged but
    never re-raised, so it never blocks the main chat response.
    """
    # Skip if DB or API are not configured.
    if not os.environ.get("DATABASE_URL") or not api_key:
        return

    # Only session-aware requests can be summarised.
    if not user_id or not character_id:
        return

    # Count actual user turns in the current history slice.
    new_turns = sum(1 for m in history if m.get("role") == "user")

    # How many new turns are needed before the next summary?
    turns_since_last = prior_turn_count % SUMMARISE_EVERY
    turns_needed = SUMMARISE_EVERY - turns_since_last

    if new_turns < turns_needed:
        return

    # Cumulative total to store with the new summary.
    total_turns = prior_turn_count + new_turns

    # Resolve the model: caller > env var > hardcoded default.
    resolved_model = (
        model
        or os.environ.get("CORTECS_SUMMARY_MODEL")
        or DEFAULT_SUMMARY_MODEL
    )

    try:
        _run_summarise(
            user_id, character_id, history,
            api_key, base_url, resolved_model, total_turns,
        )
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
    model: str,
    total_turns: int,
) -> None:
    """Build the LLM prompt, call the API, and persist the result."""
    # Take the most recent 20 messages to keep the prompt compact.
    recent = history[-20:]

    # Format conversation as plain text for the LLM.
    conversation_text = _format_history(recent)

    # Call the LLM.
    client = OpenAI(api_key=api_key, base_url=base_url)
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user",   "content": f"Conversation to summarise:\n\n{conversation_text}"},
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
        log.warning(
            "summariser: LLM returned empty summary for user=%s char=%s model=%s",
            user_id, character_id, model,
        )
        return

    # Persist: deactivate the old summary, then insert the new one.
    # total_turns is the cumulative count passed in from maybe_summarise.
    db.upsert_summary(user_id, character_id, summary_text, total_turns)
    log.info(
        "summariser: updated summary for user=%s char=%s (total=%d turns, model=%s)",
        user_id, character_id, total_turns, model,
    )


def _format_history(messages: list[dict]) -> str:
    """Convert a list of {role, content} dicts to readable plain text."""
    lines = []
    for m in messages:
        role    = m.get("role", "unknown").capitalize()
        content = (m.get("content") or "").strip()
        if content:  # skip empty messages (e.g. safety sandwich injections)
            lines.append(f"{role}: {content}")
    return "\n".join(lines)
