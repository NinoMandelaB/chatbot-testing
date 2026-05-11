-- =============================================================================
-- schema_v2.sql  —  Memory system migration
-- Run once against your PostgreSQL database.
-- Safe to re-run: all statements use IF NOT EXISTS / IF EXISTS guards.
-- =============================================================================

-- Enable pgvector extension (must be available on the server).
-- On Railway Postgres: install the pgvector plugin first in the Railway dashboard.
CREATE EXTENSION IF NOT EXISTS vector;

-- =============================================================================
-- MAIN MEMORY TABLE
-- Extends the structure you already have in your production app.
-- If you are running this in the test repo from scratch, the full CREATE is
-- below. If you already have a memory_facts table, use the ALTER block instead.
-- =============================================================================

CREATE TABLE IF NOT EXISTS memory_facts (
    memory_fact_id    SERIAL PRIMARY KEY,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Who this fact belongs to and which character context it lives in.
    -- character_id is NULL for cross-character / safety-global facts.
    user_id           TEXT NOT NULL,
    character_id      TEXT,

    -- The plain-text fact. (Encryption layer can be added later on top.)
    fact_text         TEXT NOT NULL,

    -- 'user'      — something the user told us about themselves
    -- 'character' — something the character has said/established
    -- 'system'    — written by the safety layer, never by the LLM
    fact_owner        TEXT NOT NULL DEFAULT 'user'
                          CHECK (fact_owner IN ('user', 'character', 'system')),

    -- 'user_private'    — visible only to the specific character that learned it
    -- 'cross_character' — shared across all characters for this user
    -- 'safety_global'   — safety flags; always injected, never auto-resolved
    scope             TEXT NOT NULL DEFAULT 'user_private'
                          CHECK (scope IN ('user_private', 'cross_character', 'safety_global')),

    -- 'current'    — fact is still true right now
    -- 'historical' — was true in the past, fades faster
    -- 'resolved'   — explicitly superseded; kept for audit, not injected
    temporal_tag      TEXT NOT NULL DEFAULT 'current'
                          CHECK (temporal_tag IN ('current', 'historical', 'resolved')),

    -- When the user stated this fact (may differ from created_at).
    as_of             TIMESTAMPTZ DEFAULT NOW(),
    -- Filled in when the fact is superseded by a newer fact.
    resolved_at       TIMESTAMPTZ,

    -- 0.0–1.0. Decays over time via compute_effective_confidence().
    confidence_score  FLOAT NOT NULL DEFAULT 1.0,
    -- 0.0–10.0. Safety facts get 10.0 and are always retrieved first.
    importance_score  FLOAT NOT NULL DEFAULT 1.0,
    -- Per-day exponential decay rate applied to confidence.
    -- Slower for 'current' facts, faster for 'historical'.
    decay_rate        FLOAT NOT NULL DEFAULT 0.005,

    is_active         BOOLEAN NOT NULL DEFAULT TRUE,
    expires_at        TIMESTAMPTZ,
    last_used_at      TIMESTAMPTZ,
    extracted_at      TIMESTAMPTZ DEFAULT NOW(),
    source_message_id TEXT,
    conversation_id   TEXT,
    fact_type         TEXT,

    -- Safety category tags, e.g. ARRAY['self_harm', 'violence_planning'].
    -- Stored as a native Postgres array for cheap ANY() lookups.
    trigger_tags      TEXT[] NOT NULL DEFAULT '{}',

    -- 384-dim embedding from all-MiniLM-L6-v2.
    -- Used for semantic similarity search via pgvector.
    embedding         VECTOR(384)
);

-- -----------------------------------------------------------------------------
-- Indexes
-- -----------------------------------------------------------------------------

-- Fast lookup of all active facts for a user + character.
CREATE INDEX IF NOT EXISTS idx_mf_user_char
    ON memory_facts (user_id, character_id)
    WHERE is_active = TRUE;

-- Fast lookup of safety-global facts (injected on every request).
CREATE INDEX IF NOT EXISTS idx_mf_safety
    ON memory_facts (user_id, scope)
    WHERE scope = 'safety_global' AND is_active = TRUE;

-- pgvector IVFFlat index for cosine similarity search.
-- 'lists' = sqrt(expected row count). Tune as the table grows.
CREATE INDEX IF NOT EXISTS idx_mf_embedding
    ON memory_facts USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 10);

-- -----------------------------------------------------------------------------
-- Auto-update updated_at on every row change
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_mf_updated_at ON memory_facts;
CREATE TRIGGER trg_mf_updated_at
    BEFORE UPDATE ON memory_facts
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
