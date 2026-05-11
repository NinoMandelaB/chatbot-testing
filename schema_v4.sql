-- schema_v4.sql  --  Add memory_sessions table for per-session turn counting.
--
-- The summariser needs a reliable cumulative turn counter per (user_id, character_id)
-- pair that increments on every /chat call, independently of how many summary rows
-- exist in conversation_summaries.
--
-- Run this migration once against the Railway Postgres database.
-- All statements are idempotent (safe to re-run).

-- ---------------------------------------------------------------------------
-- memory_sessions: one row per (user_id, character_id) session.
-- turn_count is atomically incremented by db.increment_and_get_turn_count()
-- on every /chat request that has a valid session context.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS memory_sessions (
    user_id      TEXT        NOT NULL,
    character_id TEXT        NOT NULL,
    turn_count   INTEGER     NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, character_id)
);

-- Auto-update updated_at on row change (reuse the trigger function already
-- created by schema_v3 for conversation_summaries).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'trg_ms_updated_at'
    ) THEN
        CREATE TRIGGER trg_ms_updated_at
        BEFORE UPDATE ON memory_sessions
        FOR EACH ROW EXECUTE FUNCTION set_updated_at();
    END IF;
END;
$$;
