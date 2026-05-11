"""
memory/  —  Memory management package for the chatbot-testing app.

Package layout
--------------
db.py          Database access layer (all SQL lives here).
embeddings.py  Sentence-transformer singleton + cosine similarity helper.
extractor.py   LLM-based fact extraction, safety flagging, resolution.
retriever.py   Ranked retrieval, confidence decay, prompt block builder.
summariser.py  Periodic conversation summarisation for long-term context.

Per-turn call order in app.py
------------------------------
1. retriever.build_memory_block()   — inject facts + summary BEFORE the LLM call
2. <main LLM call in app.py>
3. extractor.extract_and_store()    — learn new facts from user message AFTER reply
4. db.touch_last_used()             — mark injected facts as recently used
5. summariser.maybe_summarise()     — conditionally refresh long-term summary

All public functions are safe to call when DATABASE_URL is not set:
they return empty values and log a warning instead of raising.
"""
