"""
memory/summariser.py  —  Conversation summarisation for hybrid memory.

After every SUMMARISE_EVERY turns the /chat endpoint calls maybe_summarise().
This module:
  1. Builds a compact prompt from the recent conversation history.
  2. Calls the LLM to compress the conversation into a single paragraph (~150 words).
  3. Deactivates the previous summary for this (user_id, character_id) pair.
  4. Writes the new summary to conversation_summaries via memory/db.py.

The summary is later prepended to the [MEMORY] block by memory/retriever.py,
giving the LLM long-term context without consuming many tokens.

Token budget: one LLM call per SUMMARISE_EVERY turns; the call uses ~300
prompt tokens and returns ~150 tokens.  Skipped entirely when DATABASE_URL
or the API key is not configured.

Turn counting
-------------
app.py calls memory_db.increment_and_get_turn_count(user_id, character_id)
BEFORE calling maybe_summarise(), and passes the resulting cumulative turn
number as `turn_count`.  A summary is generated whenever:

    turn_count % SUMMARISE_EVERY == 0

Because the counter is incremented atomically in the DB on every /chat call,
it is completely independent of the history slice the frontend sends.

Model selection
---------------
The model used for summarisation matches the model the user selected for chat
(passed in via the `model` parameter).  If no model is provided, it falls back
to the CORTECS_SUMMARY_MODEL env var, or finally to DEFAULT_SUMMARY_MODEL.
"""
import logging
import os
from typing import Optional

from openai import OpenAI

from memory import db

log = logging.getLogger(__name__)

# How many user turns must accumulate before a new summary is generated.
# Configurable via the SUMMARISE_EVERY env var (default: 6).
SUMMARISE_EVERY: int = int(os.environ.get("SUMMARISE_EVERY", "6"))

# Fallback model when no model is passed in and the env var is not set.
DEFAULT_SUMMARY_MODEL: str = "qwen3.5-9b"

# Safety-sandwich and system-injection prefixes to strip before summarising.
# Any message whose content starts with one of these strings is excluded.
_SKIP_CONTENT_PREFIXES: tuple = (
    "[SAFETY & SCOPE REMINDER",
    "[MEMORY]",
    "[System:",
    "[NOTE:",
)

# System prompt that instructs the model to produce a terse summary.
_SYSTEM_PROMPT = (
    "You are a memory compression assistant. "
    "Given a conversation excerpt, write a single dense paragraph (max 150 words) "
    "that captures the key facts, tone, and context. "
    "Write in third person (e.g. 'The user mentioned...'). "
    "Do NOT include greetings, filler, or the word 'summary'. "
    "Return ONLY the paragraph, no markdown."
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def maybe_summarise(
    user_id: str,
    character_id: str,
    history: list[dict],
    api_key: str,
    base_url: str,
    model: Optional[str] = None,
    turn_count: int = 0,
) -> None:
    """
    Trigger a summary update if the current turn number is a multiple of
    SUMMARISE_EVERY.

    Parameters
    ----------
    user_id      : identifies the end user.
    character_id : identifies the AI character / persona.
    history      : list of {role, content} dicts -- used ONLY to build the
                   summary text.  Its length has NO effect on the trigger.
    api_key      : Cortecs API key.
    base_url     : Cortecs base URL.
    model        : LLM model name to use for summarisation.
    turn_count   : the CURRENT cumulative turn number for this session,
                   already incremented by app.py via
                   memory_db.increment_and_get_turn_count() before this call.
                   A summary fires when turn_count % SUMMARISE_EVERY == 0.
    """
    # Skip if DB or API are not configured.
    if not os.environ.get("DATABASE_URL") or not api_key:
        log.debug("summariser: skipped - DATABASE_URL or api_key missing")
        return

    # Only session-aware requests can be summarised.
    if not user_id or not character_id:
        log.debug("summariser: skipped - no user_id or character_id")
        return

    # Fire when the cumulative turn count hits an exact multiple of the interval.
    # turn_count is already the post-increment value from increment_and_get_turn_count.
    if turn_count == 0 or turn_count % SUMMARISE_EVERY != 0:
        log.debug(
            "summariser: skipped - turn_count=%d (SUMMARISE_EVERY=%d)",
            turn_count, SUMMARISE_EVERY,
        )
        return

    # Resolve the model: caller > env var > hardcoded default.
    resolved_model = (
        model
        or os.environ.get("CORTECS_SUMMARY_MODEL")
        or DEFAULT_SUMMARY_MODEL
    )

    log.info(
        "summariser: firing for user=%s char=%s turn=%d model=%s",
        user_id, character_id, turn_count, resolved_model,
    )

    try:
        _run_summarise(
            user_id,
            character_id,
            history,
            api_key,
            base_url,
            resolved_model,
            turn_count,
        )
    except Exception as exc:
        log.error("summariser.maybe_summarise failed: %s", exc, exc_info=True)


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

    # Strip safety-sandwich injections and empty messages, then take the
    # most recent 20 to keep the prompt compact.
    clean_history = _filter_history(history)
    recent = clean_history[-20:]

    if not recent:
        log.warning(
            "summariser: no usable messages after filtering for user=%s char=%s",
            user_id, character_id,
        )
        return

    # Format conversation as plain text for the LLM.
    conversation_text = _format_history(recent)
    log.debug("summariser: prompt excerpt (first 200 chars): %s", conversation_text[:200])

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

    # Robustly extract the summary text.
    # Handles standard responses and Qwen3 thinking-mode quirks where
    # `content` may be None while the real text sits elsewhere.
    summary_text = ""
    if response.choices:
        summary_text = _extract_content(response.choices[0].message)

    if not summary_text:
        log.warning(
            "summariser: LLM returned empty summary for user=%s char=%s model=%s",
            user_id, character_id, model,
        )
        log.debug("summariser: raw response: %s", response)
        return

    # Persist: deactivate the old summary, then insert the new one.
    db.upsert_summary(user_id, character_id, summary_text, total_turns)
    log.info(
        "summariser: updated summary for user=%s char=%s "
        "(total=%d turns, model=%s, chars=%d)",
        user_id, character_id, total_turns, model, len(summary_text),
    )


def _extract_content(message) -> str:
    """
    Extract the assistant's text from a chat completion message object.

    Tries the standard `content` field first.  If that is empty or None
    (can happen with Qwen3 in thinking mode even when enable_thinking=False
    due to API quirks), falls back to `reasoning_content`.
    """
    # Standard path.
    text = (getattr(message, "content", None) or "").strip()
    if text:
        return text

    # Qwen3 thinking-mode fallback: reasoning_content holds the actual reply
    # when the model emits a <think>...</think> block and content ends up empty.
    text = (getattr(message, "reasoning_content", None) or "").strip()
    if text:
        log.debug("summariser: used reasoning_content fallback")
        return text

    # Last resort: check for any dict-style extra fields.
    raw = getattr(message, "model_extra", None) or {}
    text = (raw.get("content") or raw.get("reasoning_content") or "").strip()
    return text


def _filter_history(messages: list[dict]) -> list[dict]:
    """
    Remove safety-sandwich injections and other non-conversational messages.

    A message is excluded when:
    - Its content is empty / whitespace-only.
    - Its content starts with a known injection prefix (e.g. safety reminders,
      [MEMORY] blocks, system notes).
    """
    out = []
    for m in messages:
        content = (m.get("content") or "").strip()
        # Drop empty messages.
        if not content:
            continue
        # Drop known non-conversational injections.
        if any(content.startswith(prefix) for prefix in _SKIP_CONTENT_PREFIXES):
            continue
        out.append(m)
    return out


def _format_history(messages: list[dict]) -> str:
    """Convert a list of {role, content} dicts to readable plain text."""
    lines = []
    for m in messages:
        role    = m.get("role", "unknown").capitalize()
        content = (m.get("content") or "").strip()
        if content:  # skip any remaining empties
            lines.append(f"{role}: {content}")
    return "\n".join(lines)
