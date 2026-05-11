-- =============================================================================
-- schema_v3.sql  —  Hybrid memory: conversation_summaries table
-- Run once against your PostgreSQL database (Railway or local).
-- Safe to re-run: all statements use IF NOT EXISTS guards.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- CONVERSATION SUMMARIES TABLE
-- Stores one rolling LLM-generated summary per (user_id, character_id) pair.
-- The summariser regenerates this after every N turns; older versions are
-- kept for audit (is_active = FALSE) rather than deleted outright.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS conversation_summaries (
    summary_id      SERIAL PRIMARY KEY,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Owner and character context (mirrors memory_facts key columns).
    user_id         TEXT NOT NULL,
    character_id    TEXT NOT NULL,

    -- The compressed summary text produced by the LLM.
    summary_text    TEXT NOT NULL,

    -- How many conversation turns this summary covers.
    turn_count      INT NOT NULL DEFAULT 0,

    -- Only one summary per (user_id, character_id) is active at a time.
    -- Old summaries are kept with is_active = FALSE for audit purposes.
    is_active       BOOLEAN NOT NULL DEFAULT TRUE
);

-- ---------------------------------------------------------------------------
-- Indexes
-- ---------------------------------------------------------------------------

-- Fast lookup of the active summary for a given session.
CREATE INDEX IF NOT EXISTS idx_cs_user_char_active
    ON conversation_summaries (user_id, character_id)
    WHERE is_active = TRUE;

-- ---------------------------------------------------------------------------
-- Auto-update updated_at on every row change
-- (re-uses the same trigger function created in schema_v2.sql)
-- ---------------------------------------------------------------------------
DROP TRIGGER IF EXISTS trg_cs_updated_at ON conversation_summaries;
CREATE TRIGGER trg_cs_updated_at
    BEFORE UPDATE ON conversation_summaries
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
