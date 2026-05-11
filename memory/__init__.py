"""
memory/  —  Memory management package for the chatbot-testing app.

Package layout
--------------
db.py         Database access layer (all SQL lives here).
embeddings.py Sentence-transformer singleton + cosine similarity helper.
extractor.py  LLM-based fact extraction, safety flagging, resolution.
retriever.py  Ranked retrieval, confidence decay, prompt block builder.

Typical call order per chat turn
---------------------------------
1. retriever.build_memory_block()   — BEFORE calling the main LLM
2. <main LLM call in app.py>
3. extractor.extract_and_store()    — AFTER the reply is returned
4. db.touch_last_used()             — mark injected facts as recently used

All public functions are safe to call when DATABASE_URL is not set:
they return empty values and log a warning instead of raising.
"""
