# Memory and Safety Architecture from `chatbot-testing`

## Purpose

This document explains the **core memory and safety design** used in `NinoMandelaB/chatbot-testing` and how the same concept can be transferred into the main East African chatbot. [page:1][page:2]  
The implementation in this repo is Flask-based, but the underlying pattern is framework-agnostic: build prompt context, inject memory before generation, generate a reply, then update memory after the turn. [page:2]  
That means the concept should still work in a Django Channels + Celery setup, even though transport, persistence, encryption, and job orchestration will be different. [page:2][page:3]

## High-level flow

The `/chat` endpoint documents a five-step per-turn memory pipeline:  
1. `retriever.build_memory_block()` runs **before** the LLM call. [page:2]  
2. The LLM generates the reply. [page:2]  
3. `extractor.extract_and_store()` runs **after** the reply to learn facts from the user message. [page:2]  
4. `db.touch_last_used()` updates metadata for injected facts. [page:2]  
5. `summariser.maybe_summarise()` conditionally refreshes a long-term summary. [page:2]

The same endpoint also documents the prompt order sent to the model: system prompt, optional character card, memory block, conversation history, optional safety sandwich, and finally the current user message. [page:2]  
This ordering is important because it makes memory act like hidden system context instead of visible conversation text, and it places safety instructions immediately before the live user turn when sandwich mode is enabled. [page:2]

## What the memory system is doing

The repo has a dedicated `memory/` package with `db.py`, `embeddings.py`, `extractor.py`, `retriever.py`, and `summariser.py`, which shows the design is intentionally split into storage, retrieval, extraction, embeddings, and summary responsibilities rather than one monolithic memory module. [page:1][page:2]  
Even without reading every file body, the names and the `/chat` orchestration make the architecture clear: retrieval happens before inference, extraction happens after inference, and summarisation is a periodic background-style maintenance step. [page:1][page:2]

### 1) Retrieval before generation

When a `user_id` is present, the app calls `memory_retriever.build_memory_block(user_message, user_id, character_id)` before the model request. [page:2]  
If that returns content, the memory is injected as a **separate system message**, and the code comment explicitly says this is done so the model does not confuse memory content with actual conversation turns. [page:2]  
This is the core idea you should keep in the East African chatbot as well: retrieved memory should be treated as hidden control context, not as user-visible chat history. [page:2]

### 2) Extraction after generation

After the model returns a reply, the app calls `memory_extractor.extract_and_store()` using the current `user_message`, `user_id`, `character_id`, a stable `conversation_id`, the active LLM client, the active model, and the recent history. [page:2]  
The inline comment says this step extracts and stores **facts + safety flags** from the user message, which means memory is not only personalization storage but also part of the safety state model. [page:2]  
That is a strong pattern for your main chatbot: long-term memory should store both user preferences and risk-relevant context, but the storage class and field-level encryption should be upgraded for production. [page:2]

### 3) Usage tracking and confidence maintenance

If facts were injected into the prompt, the app calls `memory_db.touch_last_used(used_fact_ids)` after generation. [page:2]  
The comment explains that this is used so confidence-decay scoring stays accurate over time, which implies memories are not treated as permanently fresh. [page:2]  
This is a good production concept because it prevents stale facts from having the same weight forever and gives you a mechanism for ranking or gradually retiring old memory entries. [page:2]

### 4) Periodic summarisation

If both `user_id` and `character_id` are present, the app creates `full_history` by appending the new user message and assistant reply to the prior history, increments the session turn counter, and then calls `memory_summariser.maybe_summarise(...)`. [page:2]  
The comments say summarisation is conditional and tied to a cumulative turn counter, not simply to how many summary rows exist. [page:2][page:3]  
This is valuable because it gives you a **hybrid memory** model: fine-grained facts in one structure and compressed conversation-level summaries in another. [page:2][page:3]

## What is stored in memory

The repo includes SQL migrations `schema_v2.sql`, `schema_v3.sql`, and `schema_v4.sql`, and the commit labels shown in the repository page describe them as adding a memory table with pgvector, scopes, decay, then a `conversation_summaries` table for hybrid memory, then a `memory_sessions` table for reliable turn counting. [page:1]  
That tells us the memory design evolved from raw facts to a fuller hybrid architecture with fact storage, summary storage, and session metadata. [page:1][page:3]

The Railway database view for `memory_facts` shows these fields: `memory_fact_id`, timestamps, `user_id`, `character_id`, `fact_text`, `fact_owner`, `scope`, `temporal_tag`, `as_of`, `resolved_at`, `confidence_score`, `importance_score`, `decay_rate`, `is_active`, `expires_at`, `last_used_at`, `extracted_at`, `source_message_id`, `conversation_id`, `fact_type`, `trigger_tags`, and `embedding`. [page:5]  
This schema is important because it shows the system is not storing memory as plain text blobs only; it stores lifecycle metadata, retrieval metadata, and vector data for semantic search. [page:5]  
For the East African chatbot, this exact schema does not need to stay identical, but the conceptual fields are strong: identity keys, scope, time-awareness, confidence, expiry, trigger tags, and embeddings. [page:5]

## Session model

`schema_v4.sql` creates a `memory_sessions` table keyed by `(user_id, character_id)` with `turn_count`, `created_at`, and `updated_at`. [page:3]  
The file comments explain that the summariser needs a reliable cumulative turn counter per user-character pair and that this counter is atomically incremented on every `/chat` request with valid session context. [page:3]  
This is a very good production pattern because summarisation should be based on stable session progression, not on inference-time heuristics. [page:3]

For the main chatbot, a Channels consumer can own the real-time session while Celery workers update memory asynchronously, but the authoritative session counter should still live in the database so multiple workers cannot drift out of sync. [page:3]  
That principle is directly compatible with Django, PostgreSQL, and Celery. [page:3]

## Safety design in this repo

The repo does **not** appear to use a separate safety microservice inside `app.py`; instead, it defines a hard-coded `SAFETY_REMINDER` and `SAFETY_ACK` and injects them as a “safety sandwich” immediately before the user message when sandwich mode is enabled. [page:2]  
The reminder explicitly includes hard-stop categories such as minor/underage sexual content, incest, bestiality, non-consent, CSAM, graphic violence against a real person, hate speech, criminal instructions, and doxxing. [page:2]  
It also includes rules for self-harm and suicide responses, including empathetic language and use of `https://findahelpline.com/`. [page:2]

This is conceptually simple but effective: instead of trusting the model to remember static safety policy from the distant system prompt, the app re-injects a condensed reminder right before the live user turn. [page:2]  
In other words, safety here is being reinforced at the exact point where the risky message is processed. [page:2]

### Safety and memory connection

The most interesting detail is that the extractor comment says it stores **facts + safety flags** from the user message. [page:2]  
That means the system is designed so risky prior behavior can become part of long-term context, not just a single-turn moderation decision. [page:2]  
You should preserve that concept in the East African chatbot, because repeated safety-relevant patterns often matter more than one isolated message. [page:2]

## Why the concept transfers well to Django Channels + Celery

The repo is Flask, but its control flow already separates into synchronous and asynchronous-friendly parts:  
- Prompt assembly and reply generation are request-path work. [page:2]  
- Fact extraction, summary refresh, and memory maintenance are post-reply work. [page:2]  
- Turn counting and stored memory are database-backed state. [page:2][page:3]

That separation maps naturally to Django Channels and Celery:  
- Channels handles websocket/session communication.  
- The LLM call can still happen in the request/consumer path when needed.  
- Celery can process extraction, embedding generation, summarisation, decay recalculation, and safety-memory enrichment after the response is already sent.  

The repo even comments that post-reply memory steps are effectively “fire-and-forget”: errors are logged and not re-raised so a memory failure does not block the chat response. [page:2]  
That principle is especially useful in production systems where user-facing latency must stay low even if summarisation or vector writes fail temporarily. [page:2]

## Recommended production adaptation for the East African chatbot

### Keep the same core pattern

Keep this sequence:  
1. Build system prompt and character configuration.  
2. Retrieve relevant memory into a hidden memory block.  
3. Add recent history.  
4. Apply current-turn safety layer.  
5. Generate response.  
6. Run extraction and safety-memory updates after the reply.  
7. Periodically summarise. [page:2]

This is the part worth reusing almost unchanged because it is the architectural core, not a Flask-specific trick. [page:2]  

### Upgrade storage and security

The current repo clearly stores memory in PostgreSQL and uses structured fields plus embeddings. [page:3][page:5]  
For the main chatbot, sensitive memory should be encrypted at rest, highly sensitive fields should use application-level encryption, and identity linkage should be separated from raw content wherever possible.  
A good production variant would store user identifiers, consent state, safety flags, and sensitive biographical facts under stricter encryption or tokenization rules than ordinary preference memory.  

### Move post-turn work to Celery

In this repo, extraction and summarisation are triggered inline after the reply, even though failures are non-blocking. [page:2]  
In the main chatbot, those steps should become Celery jobs so the websocket or HTTP response can return immediately while memory processing continues in the background.  
This is especially useful for embedding generation and summarisation, since both can add latency and cost.  

### Keep memory scopes

The `/memory/debug` route groups rows into `user_memories`, `character_memories`, and `safety_memories`, based on scopes such as `user_private`, `cross_character`, and `safety_global`. [page:2]  
That is a very useful idea for the East African chatbot because not all memory should be visible or shared in the same way. [page:2]  
A production system should formalize this into memory classes such as:  
- private user profile memory  
- per-character/session memory  
- shared cross-character preferences  
- safety/global risk memory  
- temporary short-lived conversation state  

### Keep summary + fact hybrid memory

The repo structure and schema history show a move toward hybrid memory rather than relying only on vector facts or only on conversation summaries. [page:1][page:3]  
That is the right direction for a complex chatbot, because summaries compress narrative continuity while fact rows preserve precise retrievable details. [page:1][page:3]  
For long-running character conversations, this hybrid model is much more stable than replaying raw chat logs forever. [page:2][page:3]

## Concrete implementation mapping

### In the current repo

- `app.py` is the orchestration layer. [page:2]  
- `retriever` prepares prompt-time memory. [page:1][page:2]  
- `extractor` learns new facts and safety flags after each turn. [page:1][page:2]  
- `db` tracks stored facts and turn counters. [page:1][page:2][page:3]  
- `summariser` periodically condenses longer chat history. [page:1][page:2]  
- `embeddings` likely supports semantic retrieval for stored facts, as suggested by the dedicated module and the `embedding` column in `memory_facts`. [page:1][page:5]

### In the East African chatbot

A clean production mapping would look like this:  
- **Django Channels consumer**: accepts user message, loads recent chat history, requests memory retrieval, applies safety sandwich or moderation context, and gets the reply.  
- **PostgreSQL**: stores memory facts, summaries, session counters, and safety-state metadata.  
- **Celery workers**: run extraction, embedding creation, summarisation, memory decay jobs, and safety enrichment jobs after the main reply.  
- **Encryption layer**: wraps sensitive writes and reads, especially user identity, sexual/sensitive history, and safety-related records.  
- **Audit/logging layer**: records moderation outcomes and memory mutations without exposing raw sensitive content to general logs.  

## Important caution

I was able to inspect `app.py`, the repository structure, the memory folder structure, the `memory_sessions` schema migration, and the visible `memory_facts` columns, but I was **not** able to read the raw contents of `db.py`, `extractor.py`, `retriever.py`, `summariser.py`, or `embeddings.py` in this pass. [page:1][page:2][page:3][page:5]  
So this document explains the architecture and flow with high confidence, but it should be treated as a design-level explanation rather than a line-by-line reverse engineering of those five modules. [page:1][page:2][page:3][page:5]

## Recommended next step for the developer

The developer should preserve the architecture, not necessarily the Flask code:  
- hidden memory injection before generation  
- post-turn fact extraction  
- stored safety flags  
- turn-count-driven summarisation  
- scoped memory classes  
- decay and freshness metadata  
- asynchronous background updates  
- encryption around sensitive memory  

That is the reusable concept from `chatbot-testing`, and it should translate well into the main East African chatbot with Django Channels, Celery, PostgreSQL, encryption, and stricter operational controls. [page:2][page:3][page:5]
