"""
ml_classifier.py
The platform's actual AI/ML component - a TF-IDF + Logistic Regression
text classifier, trained on bundled examples (core/ml_training_data.py)
and cached to disk after the first run.

WHY A LOCAL SKLEARN MODEL INSTEAD OF A TRANSFORMER:
An earlier version of this module used a Hugging Face transformer
(distilbert-based), which is more powerful but requires downloading
~500MB-2GB of model weights from the Hugging Face Hub on first run. For
a hackathon demo, that's a real liability - if the network is slow or
unavailable at the exact moment you're presenting, the "AI" panel goes
blank. A locally-trained scikit-learn model is smaller, trains itself in
under a second from the bundled dataset, and then runs 100% offline,
every time, with zero download risk. It's a real trained classifier
(TF-IDF features -> Logistic Regression), not a heuristic dressed up -
just a lighter one than a transformer.

UPGRADE PATH: if you want the transformer instead (e.g. for a non-demo,
production deployment where a slow download on first run is acceptable),
swap USE_TRANSFORMER_BACKEND to True below and run:
    pip install transformers torch
The rest of the pipeline (risk_engine.py, app.py, templates) doesn't
need to change - both backends return the same MLResult shape.
"""

import os
from dataclasses import dataclass
from typing import Optional

USE_TRANSFORMER_BACKEND = False  # see "UPGRADE PATH" above

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
MODEL_PATH = os.path.join(MODEL_DIR, "phishing_classifier.joblib")

_sklearn_model = None
_sklearn_load_attempted = False
_sklearn_load_error: Optional[str] = None
_training_meta = {"num_examples": 0}

_transformer_pipeline = None
_transformer_load_attempted = False
_transformer_load_error: Optional[str] = None
_TRANSFORMER_MODEL_NAME = "cybersectony/phishing-email-detection-distilbert_v2.1"


@dataclass
class MLResult:
    available: bool
    label: Optional[str] = None         # "phishing" / "legitimate"
    confidence: Optional[float] = None  # 0.0-1.0
    score_contribution: int = 0         # 0-100, how much this should weigh into fraud score
    note: str = ""
    backend: str = ""                   # "sklearn-local" | "transformer" | ""


def _train_and_save_sklearn_model():
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    import joblib
    from core.ml_training_data import get_training_data

    texts, labels = get_training_data()
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=1, stop_words="english", lowercase=True)),
        ("clf", LogisticRegression(max_iter=1000, class_weight="balanced")),
    ])
    pipeline.fit(texts, labels)

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH)
    _training_meta["num_examples"] = len(texts)
    return pipeline


def _load_sklearn_model():
    global _sklearn_model, _sklearn_load_attempted, _sklearn_load_error
    if _sklearn_load_attempted:
        return
    _sklearn_load_attempted = True
    try:
        import joblib
        from core.ml_training_data import get_training_data
        texts, _ = get_training_data()
        _training_meta["num_examples"] = len(texts)

        if os.path.exists(MODEL_PATH):
            _sklearn_model = joblib.load(MODEL_PATH)
        else:
            _sklearn_model = _train_and_save_sklearn_model()
    except Exception as e:
        _sklearn_load_error = str(e)
        _sklearn_model = None


def _load_transformer_model():
    global _transformer_pipeline, _transformer_load_attempted, _transformer_load_error
    if _transformer_load_attempted:
        return
    _transformer_load_attempted = True
    try:
        from transformers import pipeline
        _transformer_pipeline = pipeline("text-classification", model=_TRANSFORMER_MODEL_NAME, truncation=True)
    except Exception as e:
        _transformer_load_error = str(e)
        _transformer_pipeline = None


def _classify_with_sklearn(text: str) -> MLResult:
    _load_sklearn_model()
    if _sklearn_model is None:
        return MLResult(
            available=False,
            note=f"Local ML classifier unavailable ({_sklearn_load_error or 'scikit-learn not installed'}) "
                 f"- run: pip install scikit-learn joblib. Falling back to heuristic-only scoring.",
        )

    proba = _sklearn_model.predict_proba([text])[0]
    classes = list(_sklearn_model.classes_)
    phishing_idx = classes.index(1)
    phishing_prob = float(proba[phishing_idx])

    is_phishing = phishing_prob >= 0.5
    confidence = phishing_prob if is_phishing else (1.0 - phishing_prob)
    label = "phishing" if is_phishing else "legitimate"
    contribution = int(phishing_prob * 40) if is_phishing else 0

    return MLResult(
        available=True,
        label=label,
        confidence=confidence,
        score_contribution=contribution,
        note=f"Local TF-IDF + Logistic Regression classifier (trained on "
             f"{_training_meta['num_examples']} bundled examples, runs fully offline) "
             f"predicted '{label}' with {confidence:.0%} confidence",
        backend="sklearn-local",
    )


def _classify_with_transformer(text: str) -> MLResult:
    _load_transformer_model()
    if _transformer_pipeline is None:
        return MLResult(
            available=False,
            note=f"Transformer classifier unavailable ({_transformer_load_error or 'transformers not installed'}) "
                 f"- run: pip install transformers torch. Falling back to heuristic-only scoring.",
        )
    try:
        result = _transformer_pipeline(text[:2000])[0]
        label = result["label"].lower()
        confidence = float(result["score"])
        is_phishing_label = "phish" in label or label in ("fraud", "spam", "malicious")
        contribution = int(confidence * 40) if is_phishing_label else 0
        return MLResult(
            available=True,
            label=label,
            confidence=confidence,
            score_contribution=contribution,
            note=f"Transformer classifier ({_TRANSFORMER_MODEL_NAME.split('/')[-1]}) predicted "
                 f"'{label}' with {confidence:.0%} confidence",
            backend="transformer",
        )
    except Exception as e:
        return MLResult(available=False, note=f"Classification failed: {e}")


def classify_text(subject: str, body_text: str) -> MLResult:
    text = f"{subject}\n{body_text}".strip()
    if not text:
        return MLResult(available=False, note="No text content to classify")

    if USE_TRANSFORMER_BACKEND:
        return _classify_with_transformer(text)
    return _classify_with_sklearn(text)
