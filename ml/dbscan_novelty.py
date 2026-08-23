"""
DBSCAN novelty scorer.

Why not sklearn.cluster.DBSCAN directly: DBSCAN lacks a .predict() or .decision_function() method to score new, live, or held-out data against a previously fitted model.
What this does instead: Scores new points by computing their continuous distance to the $k$-th nearest training neighbor, transforming DBSCAN's core density logic into a calibratable anomaly metric.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from sklearn.neighbors import NearestNeighbors
from sklearn.preprocessing import StandardScaler

@dataclass
class DBSCANNoveltyScorer:
    """
    Fit once on clean training data, then call decision_function() on any
    new data (held-out clean sessions, live/attack graphs) to get
    DBSCAN-style density scores.
    """
    min_samples: int
    scaler: StandardScaler = None
    nn: NearestNeighbors = None

    def fit(self, X: np.ndarray) -> "DBSCANNoveltyScorer":
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        k = min(self.min_samples, max(1, X_scaled.shape[0] - 1))
        self.nn = NearestNeighbors(n_neighbors=k)
        self.nn.fit(X_scaled)
        self._effective_k = k
        return self

    def decision_function(self, X: np.ndarray) -> np.ndarray:
        if self.scaler is None or self.nn is None:
            raise RuntimeError("DBSCANNoveltyScorer must be fit() before scoring.")
        X_scaled = self.scaler.transform(X)
        distances, _ = self.nn.kneighbors(X_scaled, n_neighbors=self._effective_k)
        # distance to the FARTHEST of the k nearest neighbors 
        kth_distance = distances[:, -1]
        return -kth_distance