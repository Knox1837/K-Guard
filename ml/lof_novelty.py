"""
LOF novelty scorer with internal feature scaling and score clipping.

"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler


@dataclass
class LOFNoveltyScorer:
    """
    Fit once on clean training data, then call decision_function() on any new data (held-out clean sessions, live/attack graphs) to get scale-normalized, clipped LOF scores.
    """
    n_neighbors: int
    contamination: float
    clip_percentile: float = 1.0  # clip below the training set's 1st percentile score
    scaler: StandardScaler = None
    lof: LocalOutlierFactor = None
    _clip_floor: float = None

    def fit(self, X: np.ndarray) -> "LOFNoveltyScorer":
        # De-duplicate exact-duplicate rows before fitting.
        X_unique = np.unique(X, axis=0)
        n_dupes = X.shape[0] - X_unique.shape[0]
        if n_dupes > 0:
            print(
                f"LOFNoveltyScorer: removed {n_dupes} exact-duplicate row(s) "
                f"before fitting ({X.shape[0]} -> {X_unique.shape[0]} rows)."
            )

        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X_unique)
        effective_n = min(self.n_neighbors, max(1, X_scaled.shape[0] - 1))
        self.lof = LocalOutlierFactor(
            n_neighbors=effective_n,
            contamination=self.contamination,
            novelty=True,
        )
        self.lof.fit(X_scaled)
        self._effective_n_neighbors = effective_n

        # Establish the clip floor from the TRAINING set's own score  distribution 
        train_scores = self.lof.decision_function(X_scaled)
        self._clip_floor = float(np.percentile(train_scores, self.clip_percentile))
        print(
            f"LOFNoveltyScorer: clip floor set to {self._clip_floor:.4f} "
            f"(training set's p{self.clip_percentile} score). Raw training "
            f"score range was [{train_scores.min():.4f}, {train_scores.max():.4f}]."
        )
        return self

    def decision_function(self, X: np.ndarray) -> np.ndarray:
        if self.scaler is None or self.lof is None:
            raise RuntimeError("LOFNoveltyScorer must be fit() before scoring.")
        X_scaled = self.scaler.transform(X)
        raw_scores = self.lof.decision_function(X_scaled)

        return np.clip(raw_scores, self._clip_floor, None)