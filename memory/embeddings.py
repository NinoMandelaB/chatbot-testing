"""
memory/embeddings.py  —  Sentence-embedding utilities.

Loads all-MiniLM-L6-v2 (22 MB, 384 dimensions) once per process via a
module-level singleton. This model runs comfortably on CPU and produces
high-quality semantic embeddings at near-zero cost compared to any API.

Public API
----------
encode(text)  —  returns a plain Python list[float] ready for pgvector.
"""

import logging
from typing import Optional

log = logging.getLogger(__name__)

# Module-level singleton — loaded lazily on first call to encode().
_model = None


def _get_model():
    """Load the sentence-transformer model once and cache it."""
    global _model
    if _model is None:
        try:
            from sentence_transformers import SentenceTransformer
            _model = SentenceTransformer("all-MiniLM-L6-v2")
            log.info("memory.embeddings: model loaded (all-MiniLM-L6-v2)")
        except Exception as exc:
            log.error("memory.embeddings: failed to load model — %s", exc)
            raise
    return _model


def encode(text: str) -> Optional[list]:
    """
    Encode *text* into a 384-dimensional float vector.

    Returns None if the model is unavailable (e.g. sentence-transformers
    not installed) so the rest of the system degrades gracefully to
    keyword-only retrieval instead of crashing.
    """
    if not text or not text.strip():
        return None
    try:
        model = _get_model()
        vector = model.encode(text, normalize_embeddings=True)
        return vector.tolist()
    except Exception as exc:
        log.warning("memory.embeddings.encode failed: %s", exc)
        return None


def cosine_similarity(a: list, b: list) -> float:
    """
    Pure-Python cosine similarity between two equal-length float lists.
    Used only for in-process re-ranking; pgvector handles DB-side search.
    """
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = sum(x * x for x in a) ** 0.5
    norm_b = sum(x * x for x in b) ** 0.5
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)
