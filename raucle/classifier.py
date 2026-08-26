"""Heuristic and optional ML classifier for semantic prompt-injection detection.

When ``transformers`` and ``torch`` are installed and a local model checkpoint
exists, the classifier will use a fine-tuned DeBERTa-v3-small (or compatible)
model.  Otherwise it falls back to a lightweight keyword-density heuristic that
works without any external dependencies.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Weighted signal dictionaries
# ---------------------------------------------------------------------------

INJECTION_SIGNALS: dict[str, float] = {
    # (keyword, weight) -- higher weight = stronger signal
    "ignore all previous": 0.25,
    "ignore above": 0.20,
    "disregard your instructions": 0.25,
    "new instructions": 0.15,
    "system prompt": 0.18,
    "print your": 0.15,
    "show me your": 0.12,
    "show your": 0.12,
    "display your": 0.12,
    "you are now": 0.12,
    "act as": 0.08,
    "pretend to be": 0.10,
    "developer mode": 0.15,
    "do anything now": 0.20,
    "jailbreak": 0.18,
    "bypass": 0.10,
    "override": 0.10,
    "forget everything": 0.20,
    "no restrictions": 0.15,
    "without filters": 0.12,
    "unlimited mode": 0.15,
    "ignore safety": 0.20,
    "reveal your": 0.12,
    "output your": 0.10,
}

BENIGN_SIGNALS: dict[str, float] = {
    "how do i": 0.10,
    "can you help": 0.08,
    "please explain": 0.08,
    "what is": 0.06,
    "tell me about": 0.06,
    "i need help": 0.08,
    "thank you": 0.06,
    "summarize": 0.05,
    "translate": 0.05,
    "write a": 0.04,
}

# Negation patterns that appear within a short span before an injection keyword
_NEGATION_PATTERN = re.compile(r"(?:don['\u2019]t|do not|never|shouldn['\u2019]t)", re.IGNORECASE)
_NEGATION_WINDOW = 40  # characters before the match start


class HeuristicClassifier:
    """Weighted keyword classifier with position awareness, negation detection,
    and density scoring.

    Scores text by matching injection and benign signal phrases with individual
    weights, then applies position bonuses, negation reductions, and density
    bonuses to produce a 0-1 confidence score.
    """

    def classify(self, text: str) -> dict[str, Any]:
        text_lower = text.lower()

        injection_score, injection_hits = self._score_injection(text_lower)
        injection_score = self._apply_density_bonus(injection_score, injection_hits)
        injection_score = min(1.0, injection_score)

        benign_score = self._score_benign(text_lower)

        score = max(0.0, min(1.0, injection_score - (benign_score * 0.5)))

        categories: list[str] = []
        technique = ""
        if score > 0.5:
            categories = ["heuristic_injection"]
            technique = "heuristic_detection"

        return {
            "score": round(score, 4),
            "categories": categories,
            "technique": technique,
        }

    @staticmethod
    def _score_injection(
        text_lower: str,
    ) -> tuple[float, list[tuple[str, int]]]:
        """Sum weighted injection signals with position/negation adjustments."""
        injection_score = 0.0
        injection_hits: list[tuple[str, int]] = []

        opening = text_lower[:100]
        benign_in_opening = any(kw in opening for kw in BENIGN_SIGNALS)

        for keyword, weight in INJECTION_SIGNALS.items():
            pos = text_lower.find(keyword)
            if pos == -1:
                continue

            effective_weight = weight

            if pos < 100 and not benign_in_opening:
                effective_weight *= 1.5

            window_start = max(0, pos - _NEGATION_WINDOW)
            preceding = text_lower[window_start:pos]
            if _NEGATION_PATTERN.search(preceding):
                effective_weight *= 0.3

            injection_score += effective_weight
            injection_hits.append((keyword, pos))

        return injection_score, injection_hits

    @staticmethod
    def _apply_density_bonus(
        injection_score: float, injection_hits: list[tuple[str, int]]
    ) -> float:
        """Add a density bonus when 3+ injection signals cluster in a 200-char window."""
        if len(injection_hits) < 3:
            return injection_score

        positions = sorted(h[1] for h in injection_hits)
        for i in range(len(positions)):
            window_end = positions[i] + 200
            count_in_window = sum(1 for p in positions if positions[i] <= p <= window_end)
            if count_in_window >= 3:
                injection_score += 0.1
                break
        return injection_score

    @staticmethod
    def _score_benign(text_lower: str) -> float:
        """Sum weighted benign signals (capped at 0.5)."""
        benign_score = 0.0
        for keyword, weight in BENIGN_SIGNALS.items():
            if keyword in text_lower:
                benign_score += weight
        return min(0.5, benign_score)


class MLClassifier:
    """Transformer-based classifier (optional -- requires ``transformers`` and ``torch``)."""

    def __init__(self) -> None:
        self._model: Any = None
        self._tokenizer: Any = None
        self._available = False

    def load(self, model_path: str | None = None) -> bool:
        """Attempt to load a local model checkpoint.

        Returns ``True`` if the model was loaded successfully.
        """
        from raucle._env import env as _env

        model_path = model_path or _env("MODEL_PATH", "./models")
        local_dir = os.path.join(model_path, "semantic-classifier")

        if not os.path.isdir(local_dir):
            logger.debug("No local model at %s -- ML classifier not available", local_dir)
            return False

        try:
            from transformers import (  # type: ignore[import-untyped]
                AutoModelForSequenceClassification,
                AutoTokenizer,
            )

            self._tokenizer = AutoTokenizer.from_pretrained(local_dir)
            self._model = AutoModelForSequenceClassification.from_pretrained(local_dir)
            self._model.eval()
            self._available = True
            logger.info("Loaded semantic model from %s", local_dir)
            return True
        except ImportError:
            logger.info("transformers package not installed -- ML classifier disabled")
            return False
        except Exception as exc:
            logger.warning("Failed to load ML model: %s", exc)
            return False

    @property
    def available(self) -> bool:
        return self._available

    def classify(self, text: str) -> dict[str, Any]:
        """Run text through the transformer and return a score dict."""
        if not self._available or self._model is None:
            raise RuntimeError("ML classifier is not loaded")

        import torch  # type: ignore[import-untyped]

        inputs = self._tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=512,
            padding=True,
        )
        with torch.no_grad():
            outputs = self._model(**inputs)
            probs = torch.softmax(outputs.logits, dim=-1)
            injection_prob: float = probs[0][1].item()

        categories: list[str] = []
        technique = ""
        if injection_prob > 0.7:
            categories = ["semantic_injection"]
            technique = "semantic_detection"

        return {
            "score": round(injection_prob, 4),
            "categories": categories,
            "technique": technique,
        }
