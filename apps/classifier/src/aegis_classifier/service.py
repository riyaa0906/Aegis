"""Local prompt-injection classifier, served over HTTP for the Aegis gateway.

The model is deberta-v3-base-prompt-injection-v2, run locally: tool output is never sent to
a third-party inference API. It reports a probability, not a verdict -- the gateway owns the
thresholds and the decision.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

MODEL = os.environ.get("AEGIS_CLASSIFIER_MODEL", "protectai/deberta-v3-base-prompt-injection-v2")
# The model truncates at 512 tokens, so long output is scored in windows and the worst
# window wins: an injection buried at the end must not be truncated away.
WINDOW_CHARS = int(os.environ.get("AEGIS_CLASSIFIER_WINDOW_CHARS", "1200"))


@lru_cache(maxsize=1)
def _pipeline() -> Any:
    from transformers import pipeline

    return pipeline("text-classification", model=MODEL, truncation=True, max_length=512)


def windows(text: str, size: int = WINDOW_CHARS) -> list[str]:
    if not text:
        return [""]
    # Half-overlapping windows, so a payload split across a boundary is still seen whole.
    step = max(size // 2, 1)
    return [text[start : start + size] for start in range(0, max(len(text) - step, 1), step)]


def injection_score(text: str, classify: Any | None = None) -> float:
    classify = classify or _pipeline()
    scores = []
    for prediction in classify(windows(text)):
        probability = float(prediction["score"])
        scores.append(probability if prediction["label"] == "INJECTION" else 1.0 - probability)
    return max(scores)


class ClassifyRequest(BaseModel):
    text: str


class ClassifyResponse(BaseModel):
    score: float
    model: str


app = FastAPI(title="aegis-classifier")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "model": MODEL}


@app.post("/classify")
def classify(request: ClassifyRequest) -> ClassifyResponse:
    return ClassifyResponse(score=injection_score(request.text), model=MODEL)
