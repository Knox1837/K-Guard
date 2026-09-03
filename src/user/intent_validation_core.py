"""
intent_validation_core.py: pluggable Section 3.6.3 intent validation backends.

This module keeps the public validation API stable for graphengine.py and
graphengine_live.py while making the step-3 justification test selectable
between the historical keyword rule, a lightweight TF-IDF similarity model,
and a local sentence-embedding backend.
"""
from __future__ import annotations

import json
import os
import pickle
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path
from typing import Optional, Protocol, runtime_checkable

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

REPO_ROOT = Path(__file__).resolve().parents[2]
BENCHMARK_DIR = REPO_ROOT / "benchmarks" / "intent_aware"
ARTIFACT_DIR = BENCHMARK_DIR / "artifacts"
DEFAULT_VALIDATION_CONFIG_PATH = BENCHMARK_DIR / "intent_validation_config.json"
DEFAULT_TFIDF_VECTORIZER_PATH = ARTIFACT_DIR / "tfidf_vectorizer.pkl"
DEFAULT_EMBEDDING_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"

SENSITIVE_PATH_PATTERNS = [".ssh/", "/etc/shadow", ".gnupg/", ".env", "credentials"]

SENSITIVE_PATH_DESCRIPTIONS = {
    ".ssh/": "SSH private keys, authorized_keys, known_hosts, and other ~/.ssh material",
    "/etc/shadow": "Linux password hash database in /etc/shadow",
    ".gnupg/": "GPG and GNUPG keyring material, including secret keys",
    ".env": "dotenv configuration files and environment secrets",
    "credentials": "API credentials, tokens, secrets, and deployment keys",
}

_PATTERN_KEYWORDS = {
    ".ssh/": ("ssh", "id_rsa", "id_ed25519", "known_hosts", "authorized_keys", "ssh key"),
    "/etc/shadow": ("shadow", "password hash", "/etc/shadow"),
    ".gnupg/": ("gnupg", "gpg", "pgp key"),
    ".env": (".env", "environment variable", "env file", "dotenv"),
    "credentials": ("credential", "api key", "secret", "token"),
}


@runtime_checkable
class IntentValidationBackend(Protocol):
    name: str

    def is_justified(self, task_description: str, path: str, pattern: str) -> float:
        """Return a justification score in [0, 1]; higher means more justified."""


def is_sensitive_path(path: str) -> Optional[str]:
    """Return the matching sensitive-pattern string, or None if `path` is not sensitive."""
    if not path:
        return None
    for pattern in SENSITIVE_PATH_PATTERNS:
        if pattern in path:
            return pattern
    return None


def describe_sensitive_path(path: str, pattern: str) -> str:
    """Return the text used by similarity backends to represent a sensitive access."""
    basename = path.rsplit("/", 1)[-1].strip()
    pattern_description = SENSITIVE_PATH_DESCRIPTIONS.get(pattern, pattern)
    if basename:
        return f"{pattern_description}. Accessed path basename: {basename}."
    return pattern_description


def path_referenced_in_intent(path: str, task_description: str, pattern: str) -> bool:
    """
    Historical keyword rule for Section 3.6.3.

    Checks, in order:
      (a) the pattern's own text appearing literally in the task description,
      (b) the file's basename appearing literally in the task description,
      (c) the curated keyword set for that pattern.
    """
    if not task_description:
        return False

    text = task_description.lower()
    if pattern.strip("/.").lower() in text:
        return True

    basename = path.rsplit("/", 1)[-1].lower()
    if basename and basename in text:
        return True

    for kw in _PATTERN_KEYWORDS.get(pattern, ()):  # curated keyword fallback
        if kw.lower() in text:
            return True

    return False


@dataclass(frozen=True)
class IntentViolation:
    """Result of a failed Section 3.6.3 validation, ready for graph annotation."""

    pid: int
    path: str
    pattern: str
    task_description: str

    def as_dict(self) -> dict:
        return {
            "pid": self.pid,
            "path": self.path,
            "matched_pattern": self.pattern,
            "task_description": self.task_description,
        }


class KeywordIntentValidationBackend:
    name = "keyword"

    def is_justified(self, task_description: str, path: str, pattern: str) -> float:
        return 1.0 if path_referenced_in_intent(path, task_description, pattern) else 0.0


class TfidfIntentValidationBackend:
    name = "tfidf"

    def __init__(self, vectorizer: TfidfVectorizer):
        self._vectorizer = vectorizer
        self._pattern_vectors = {
            pattern: self._vectorizer.transform([describe_sensitive_path(pattern, pattern)])
            for pattern in SENSITIVE_PATH_PATTERNS
        }

    @lru_cache(maxsize=256)
    def _task_vector(self, task_description: str):
        return self._vectorizer.transform([task_description])

    def is_justified(self, task_description: str, path: str, pattern: str) -> float:
        if not task_description:
            return 0.0
        task_vector = self._task_vector(task_description)
        pattern_vector = self._pattern_vectors[pattern]
        score = cosine_similarity(task_vector, pattern_vector)[0, 0]
        return float(score)


class EmbeddingIntentValidationBackend:
    name = "embedding"

    def __init__(self, model_name: str = DEFAULT_EMBEDDING_MODEL_NAME):
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise RuntimeError(
                "sentence-transformers is required for the embedding backend. "
                "Install requirements.txt or select the keyword/tfidf backend."
            ) from exc

        self._model_name = model_name
        self._model = SentenceTransformer(model_name)
        self._pattern_embeddings = {
            pattern: self._encode(describe_sensitive_path(pattern, pattern))
            for pattern in SENSITIVE_PATH_PATTERNS
        }

    @lru_cache(maxsize=256)
    def _encode(self, text: str) -> np.ndarray:
        embedding = self._model.encode(text, convert_to_numpy=True, normalize_embeddings=True)
        return np.asarray(embedding, dtype=np.float32)

    def is_justified(self, task_description: str, path: str, pattern: str) -> float:
        if not task_description:
            return 0.0
        task_embedding = self._encode(task_description)
        pattern_embedding = self._pattern_embeddings[pattern]
        return float(np.dot(task_embedding, pattern_embedding))


@dataclass(frozen=True)
class IntentValidationConfig:
    backend: str = "keyword"
    threshold: float = 0.5
    tfidf_vectorizer_path: str = str(DEFAULT_TFIDF_VECTORIZER_PATH)
    embedding_model_name: str = DEFAULT_EMBEDDING_MODEL_NAME
    source: str = "env"

    @classmethod
    def from_mapping(cls, mapping: dict, *, fallback_backend: str = "keyword") -> "IntentValidationConfig":
        backend = str(mapping.get("backend", fallback_backend)).strip().lower() or fallback_backend
        return cls(
            backend=backend,
            threshold=float(mapping.get("threshold", 0.5)),
            tfidf_vectorizer_path=str(mapping.get("tfidf_vectorizer_path", DEFAULT_TFIDF_VECTORIZER_PATH)),
            embedding_model_name=str(mapping.get("embedding_model_name", DEFAULT_EMBEDDING_MODEL_NAME)),
            source=str(mapping.get("source", "file")),
        )

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class IntentValidationRuntime:
    backend: IntentValidationBackend
    config: IntentValidationConfig


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text())


def load_validation_config(config_path: str | Path | None = None) -> IntentValidationConfig:
    """Load an explicit validation config, or fall back to the default keyword config."""
    if config_path is None:
        env_path = os.getenv("KGUARD_INTENT_VALIDATION_CONFIG")
        if env_path:
            config_path = env_path

    if config_path is None:
        backend_override = os.getenv("KGUARD_INTENT_VALIDATION_BACKEND", "keyword")
        return IntentValidationConfig(backend=backend_override.strip().lower() or "keyword", source="env-default")

    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Intent validation config not found: {path}")
    return IntentValidationConfig.from_mapping(_read_json(path), fallback_backend=os.getenv("KGUARD_INTENT_VALIDATION_BACKEND", "keyword"))


def _load_tfidf_vectorizer(vectorizer_path: str | Path) -> TfidfVectorizer:
    path = Path(vectorizer_path)
    if not path.exists():
        raise FileNotFoundError(
            f"TF-IDF vectorizer not found at {path}. Run the benchmark calibration harness to create it."
        )
    with path.open("rb") as handle:
        vectorizer = pickle.load(handle)
    if not isinstance(vectorizer, TfidfVectorizer):
        raise TypeError(f"{path} does not contain a TfidfVectorizer instance")
    return vectorizer


def load_backend(config: IntentValidationConfig | None = None) -> IntentValidationRuntime:
    config = config or load_validation_config()
    backend_name = config.backend.lower().strip()

    if backend_name == "keyword":
        backend = KeywordIntentValidationBackend()
        return IntentValidationRuntime(backend=backend, config=config)

    if backend_name == "tfidf":
        vectorizer = _load_tfidf_vectorizer(config.tfidf_vectorizer_path)
        backend = TfidfIntentValidationBackend(vectorizer)
        return IntentValidationRuntime(backend=backend, config=config)

    if backend_name == "embedding":
        backend = EmbeddingIntentValidationBackend(config.embedding_model_name)
        return IntentValidationRuntime(backend=backend, config=config)

    raise ValueError(f"Unknown intent validation backend: {config.backend!r}")


def save_validation_config(config: IntentValidationConfig, path: str | Path = DEFAULT_VALIDATION_CONFIG_PATH) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(config.as_dict(), indent=2, sort_keys=True))
    return target


def calibrate_threshold(scores: list[float], labels: list[int]) -> tuple[float, dict]:
    """
    Pick the threshold that maximizes F1 for the violation class.

    Labels are expected to be 1 for violation and 0 for justified.
    The backend predicts violation when score < threshold.
    """
    if len(scores) != len(labels):
        raise ValueError("scores and labels must have the same length")
    if not scores:
        raise ValueError("cannot calibrate a threshold from an empty score list")

    pairs = sorted((float(s), int(y)) for s, y in zip(scores, labels))
    unique_scores = sorted({score for score, _ in pairs})
    candidates = [unique_scores[0] - 1e-9]
    candidates.extend((left + right) / 2.0 for left, right in zip(unique_scores, unique_scores[1:]))
    candidates.append(unique_scores[-1] + 1e-9)

    best = {
        "threshold": candidates[0],
        "f1": -1.0,
        "precision": 0.0,
        "recall": 0.0,
        "tp": 0,
        "fp": 0,
        "tn": 0,
        "fn": 0,
    }

    for threshold in candidates:
        tp = fp = tn = fn = 0
        for score, label in pairs:
            predicted_violation = score < threshold
            if predicted_violation and label == 1:
                tp += 1
            elif predicted_violation and label == 0:
                fp += 1
            elif not predicted_violation and label == 0:
                tn += 1
            else:
                fn += 1

        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0

        if f1 > best["f1"]:
            best.update(
                {
                    "threshold": threshold,
                    "f1": f1,
                    "precision": precision,
                    "recall": recall,
                    "tp": tp,
                    "fp": fp,
                    "tn": tn,
                    "fn": fn,
                }
            )

    return best["threshold"], best


_ACTIVE_RUNTIME: IntentValidationRuntime | None = None


def get_active_validation_runtime() -> IntentValidationRuntime:
    global _ACTIVE_RUNTIME
    if _ACTIVE_RUNTIME is None:
        _ACTIVE_RUNTIME = load_backend()
    return _ACTIVE_RUNTIME


def reset_active_validation_runtime() -> None:
    global _ACTIVE_RUNTIME
    _ACTIVE_RUNTIME = None


def validate_open_event(pid: int, path: str, task_description: Optional[str]) -> Optional[IntentViolation]:
    """Validate one FILE_OPEN event using the selected backend."""
    if task_description is None:
        return None

    pattern = is_sensitive_path(path)
    if pattern is None:
        return None

    runtime = get_active_validation_runtime()
    score = runtime.backend.is_justified(task_description, path, pattern)
    if score >= runtime.config.threshold:
        return None

    return IntentViolation(pid=pid, path=path, pattern=pattern, task_description=task_description)


def score_open_event(task_description: str, path: str, backend: IntentValidationBackend) -> float:
    """Score a sensitive path access against a chosen backend without applying a threshold."""
    pattern = is_sensitive_path(path)
    if pattern is None:
        return 1.0
    return backend.is_justified(task_description, path, pattern)
