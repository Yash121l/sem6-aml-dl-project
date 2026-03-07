"""
src/models.py
=============
Anomaly detection model wrappers for the Adaptive Cyber-Physical Security project.

Provides:
  - AnomalyDetector   : abstract base class
  - IsolationForestDetector
  - OCSVMDetector
  - GMMDetector

All detectors share a common interface: fit / predict / score / evaluate / save / load.

Usage
-----
>>> from src.models import GMMDetector
>>> model = GMMDetector(n_components=12, covariance_type="full")
>>> model.fit(X_train)
>>> metrics = model.evaluate(X_test, y_test)
>>> print(metrics)
>>> model.save("models/model_a_gmm.pkl")
"""

from __future__ import annotations

import abc
import pathlib
from typing import Any, Dict, Optional, Union

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    auc,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.mixture import GaussianMixture
from sklearn.svm import OneClassSVM


# ──────────────────────────────────────────────────────────────────────────────
# Base class
# ──────────────────────────────────────────────────────────────────────────────

class AnomalyDetector(abc.ABC):
    """
    Abstract base class for one-class anomaly detection models.

    All subclasses are trained exclusively on normal (benign) data.
    The positive class (anomaly / attack) appears only at evaluation time.

    Subclasses must implement: fit, predict, score.
    """

    @abc.abstractmethod
    def fit(self, X_train: np.ndarray) -> "AnomalyDetector":
        """
        Train the model on normal (benign-only) data.

        Parameters
        ----------
        X_train : np.ndarray, shape (n_samples, n_features)
            Normal traffic feature matrix.

        Returns
        -------
        self
        """

    @abc.abstractmethod
    def predict(self, X_test: np.ndarray) -> np.ndarray:
        """
        Return binary predictions for test samples.

        Parameters
        ----------
        X_test : np.ndarray, shape (n_samples, n_features)

        Returns
        -------
        np.ndarray of int, shape (n_samples,)
            1 = anomaly (attack), 0 = normal (benign).
        """

    @abc.abstractmethod
    def score(self, X_test: np.ndarray) -> np.ndarray:
        """
        Return a continuous anomaly score for each test sample.

        Higher values indicate greater anomaly likelihood.

        Parameters
        ----------
        X_test : np.ndarray, shape (n_samples, n_features)

        Returns
        -------
        np.ndarray of float, shape (n_samples,)
        """

    def evaluate(
        self, X_test: np.ndarray, y_test: np.ndarray
    ) -> Dict[str, float]:
        """
        Compute a full set of evaluation metrics.

        Parameters
        ----------
        X_test : np.ndarray, shape (n_samples, n_features)
        y_test : np.ndarray of int, shape (n_samples,)
            Binary ground-truth labels: 1 = attack, 0 = benign.

        Returns
        -------
        dict with keys:
            precision, recall, f1, auc_roc, tp, fp, tn, fn, fpr, fnr
        """
        y_pred = self.predict(X_test)
        y_scores = self.score(X_test)

        precision = float(precision_score(y_test, y_pred, zero_division=0))
        recall    = float(recall_score(y_test, y_pred, zero_division=0))
        f1        = float(f1_score(y_test, y_pred, zero_division=0))
        try:
            auc_roc = float(roc_auc_score(y_test, y_scores))
        except ValueError:
            auc_roc = float("nan")

        cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)

        n_neg = tn + fp
        n_pos = tp + fn
        fpr = fp / n_neg if n_neg > 0 else 0.0
        fnr = fn / n_pos if n_pos > 0 else 0.0

        return {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "auc_roc": auc_roc,
            "tp": int(tp),
            "fp": int(fp),
            "tn": int(tn),
            "fn": int(fn),
            "fpr": fpr,
            "fnr": fnr,
        }

    def save(self, path: Union[str, pathlib.Path]) -> None:
        """
        Persist the model to disk using joblib.

        Parameters
        ----------
        path : str or Path
            File path (conventionally *.pkl).
        """
        path = pathlib.Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)
        print(f"Saved → {path}")

    @classmethod
    def load(cls, path: Union[str, pathlib.Path]) -> "AnomalyDetector":
        """
        Load a persisted model from disk.

        Parameters
        ----------
        path : str or Path

        Returns
        -------
        AnomalyDetector subclass instance
        """
        return joblib.load(path)


# ──────────────────────────────────────────────────────────────────────────────
# Isolation Forest
# ──────────────────────────────────────────────────────────────────────────────

class IsolationForestDetector(AnomalyDetector):
    """
    Isolation Forest anomaly detector.

    Isolation Forest (Liu et al., 2008) builds an ensemble of random trees
    that partition the feature space.  Anomalies are isolated with shorter
    average path lengths than normal points.

    Anomaly score: s(x, n) = 2^{-E[h(x)] / c(n)}
    where h(x) is the path length and c(n) is the expected path length of
    an unsuccessful binary search tree search over n samples.

    Parameters
    ----------
    n_estimators : int
        Number of isolation trees (default 50).
    contamination : float
        Expected fraction of anomalies — sets the decision threshold
        (default 0.15, best found in Stage 3 grid search).
    max_features : float
        Fraction of features to consider per split (default 0.5).
    random_state : int
        Random seed for reproducibility.
    """

    def __init__(
        self,
        n_estimators: int = 50,
        contamination: float = 0.15,
        max_features: float = 0.5,
        random_state: int = 42,
    ) -> None:
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.max_features = max_features
        self.random_state = random_state
        self._clf: Optional[IsolationForest] = None

    def fit(self, X_train: np.ndarray) -> "IsolationForestDetector":
        """Train Isolation Forest on normal data."""
        self._clf = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            max_features=self.max_features,
            random_state=self.random_state,
            n_jobs=-1,
        )
        self._clf.fit(X_train)
        return self

    def predict(self, X_test: np.ndarray) -> np.ndarray:
        """Return binary predictions (1=anomaly, 0=normal)."""
        raw = self._clf.predict(X_test)     # sklearn: -1=anomaly, 1=normal
        return (raw == -1).astype(int)

    def score(self, X_test: np.ndarray) -> np.ndarray:
        """
        Return anomaly scores.

        Negated decision_function so higher = more anomalous (consistent
        with the convention used in evaluate()).
        """
        return -self._clf.decision_function(X_test)


# ──────────────────────────────────────────────────────────────────────────────
# One-Class SVM
# ──────────────────────────────────────────────────────────────────────────────

class OCSVMDetector(AnomalyDetector):
    """
    One-Class SVM anomaly detector.

    Finds a hypersphere in the kernel-induced feature space that encloses
    most of the training data.  At test time, samples outside the boundary
    are classified as anomalies.

    Optimization objective (Schölkopf et al., 2001):
        min_{w, xi, rho}  1/2 ||w||^2 - rho + 1/(nu*n) sum_i xi_i
        s.t.  (w · phi(x_i)) >= rho - xi_i,  xi_i >= 0

    Parameters
    ----------
    nu : float
        Upper bound on fraction of training errors and lower bound on
        fraction of support vectors (default 0.2).
    kernel : str
        Kernel type: 'rbf', 'poly', or 'sigmoid' (default 'rbf').
    gamma : float or str
        Kernel coefficient (default 0.1, best found in Stage 3).
    train_cap : int
        Maximum training samples (OCSVM is O(n^2); default 8000).
    """

    def __init__(
        self,
        nu: float = 0.2,
        kernel: str = "rbf",
        gamma: Union[float, str] = 0.1,
        train_cap: int = 8_000,
    ) -> None:
        self.nu = nu
        self.kernel = kernel
        self.gamma = gamma
        self.train_cap = train_cap
        self._clf: Optional[OneClassSVM] = None

    def fit(self, X_train: np.ndarray) -> "OCSVMDetector":
        """
        Train One-Class SVM.

        Subsamples to ``train_cap`` rows if needed to keep training tractable.
        """
        if len(X_train) > self.train_cap:
            idx = np.random.choice(len(X_train), self.train_cap, replace=False)
            X_fit = X_train[idx]
        else:
            X_fit = X_train
        self._clf = OneClassSVM(
            kernel=self.kernel, nu=self.nu, gamma=self.gamma
        )
        self._clf.fit(X_fit)
        return self

    def predict(self, X_test: np.ndarray) -> np.ndarray:
        """Return binary predictions (1=anomaly, 0=normal)."""
        raw = self._clf.predict(X_test)
        return (raw == -1).astype(int)

    def score(self, X_test: np.ndarray) -> np.ndarray:
        """Return anomaly scores (negated decision function)."""
        return -self._clf.decision_function(X_test)


# ──────────────────────────────────────────────────────────────────────────────
# Gaussian Mixture Model  (Model A)
# ──────────────────────────────────────────────────────────────────────────────

class GMMDetector(AnomalyDetector):
    """
    Gaussian Mixture Model anomaly detector (Model A).

    Models the density of normal traffic as a weighted sum of K Gaussians:
        p(x) = sum_{k=1}^K pi_k * N(x | mu_k, Sigma_k)

    Anomaly score = -log p(x).  A sample is flagged as anomalous if its
    log-likelihood falls below the τ-th percentile of training log-likelihoods:
        y_hat = 1  if  log p(x) < tau,  else 0

    EM parameter estimation:
        E-step: r_{ik} = pi_k N(x_i | mu_k, Sigma_k) / p(x_i)
        M-step:
            pi_k  = (1/n) sum_i r_{ik}
            mu_k  = sum_i r_{ik} x_i / sum_i r_{ik}
            Sig_k = sum_i r_{ik} (x_i - mu_k)(x_i - mu_k)^T / sum_i r_{ik}

    Parameters
    ----------
    n_components : int
        Number of Gaussian components (default 12, chosen by BIC in Stage 3).
    covariance_type : str
        'full' (each component has its own dense covariance matrix),
        'tied', 'diag', or 'spherical' (default 'full').
    threshold_percentile : int
        Percentile of train log-likelihoods used as decision boundary τ
        (default 11, chosen by Stage 3 threshold sensitivity analysis).
    n_init : int
        Number of random restarts for EM (default 3).
    max_iter : int
        Maximum EM iterations (default 200).
    random_state : int
        Random seed.
    tune_subsample : int
        Cap on training samples for EM (default 80_000).
    """

    def __init__(
        self,
        n_components: int = 12,
        covariance_type: str = "full",
        threshold_percentile: int = 11,
        n_init: int = 3,
        max_iter: int = 200,
        random_state: int = 42,
        tune_subsample: int = 80_000,
    ) -> None:
        self.n_components = n_components
        self.covariance_type = covariance_type
        self.threshold_percentile = threshold_percentile
        self.n_init = n_init
        self.max_iter = max_iter
        self.random_state = random_state
        self.tune_subsample = tune_subsample
        self._clf: Optional[GaussianMixture] = None
        self._threshold: Optional[float] = None

    def fit(self, X_train: np.ndarray) -> "GMMDetector":
        """
        Fit GMM on normal data using EM.

        Subsamples to ``tune_subsample`` rows for tractability, then sets
        the decision threshold τ at the ``threshold_percentile``-th percentile
        of in-sample log-likelihoods.
        """
        if len(X_train) > self.tune_subsample:
            idx = np.random.choice(len(X_train), self.tune_subsample, replace=False)
            X_fit = X_train[idx]
        else:
            X_fit = X_train

        self._clf = GaussianMixture(
            n_components=self.n_components,
            covariance_type=self.covariance_type,
            n_init=self.n_init,
            max_iter=self.max_iter,
            random_state=self.random_state,
        )
        self._clf.fit(X_fit)

        # Set decision threshold from training log-likelihoods
        train_ll = self._clf.score_samples(X_fit)
        self._threshold = float(
            np.percentile(train_ll, self.threshold_percentile)
        )
        return self

    def predict(self, X_test: np.ndarray) -> np.ndarray:
        """Return binary predictions (1=anomaly, 0=normal)."""
        ll = self._clf.score_samples(X_test)
        return (ll < self._threshold).astype(int)

    def score(self, X_test: np.ndarray) -> np.ndarray:
        """
        Return anomaly scores = -log p(x).

        Higher values indicate greater anomaly likelihood.
        """
        return -self._clf.score_samples(X_test)

    @property
    def threshold(self) -> Optional[float]:
        """Decision threshold τ (log-likelihood value)."""
        return self._threshold


# ──────────────────────────────────────────────────────────────────────────────
# Smoke test
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import pathlib
    import tempfile

    ROOT = pathlib.Path(__file__).parent.parent
    prep = ROOT / "outputs" / "preprocessing"

    print("Loading data …")
    X_train = np.load(prep / "X_train.npy")
    X_test  = np.load(prep / "X_test.npy")
    y_test  = np.load(prep / "y_test.npy")

    print(f"  X_train: {X_train.shape}  X_test: {X_test.shape}")

    for DetectorCls, kwargs, name in [
        (IsolationForestDetector, {"n_estimators": 50, "contamination": 0.15}, "IsoForest"),
        (OCSVMDetector,           {"nu": 0.2, "gamma": 0.1},                   "OCSVM"),
        (GMMDetector,             {"n_components": 12},                         "GMM"),
    ]:
        print(f"\nFitting {name} …")
        det = DetectorCls(**kwargs)
        det.fit(X_train)
        metrics = det.evaluate(X_test, y_test)
        print(
            f"  F1={metrics['f1']:.4f}  "
            f"AUC={metrics['auc_roc']:.4f}  "
            f"P={metrics['precision']:.4f}  "
            f"R={metrics['recall']:.4f}"
        )

    print("\nSmoke test passed.")
