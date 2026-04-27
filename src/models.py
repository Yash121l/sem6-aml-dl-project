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
# LSTM Autoencoder  (Model B — Phase 2)
# ──────────────────────────────────────────────────────────────────────────────

class LSTMAEDetector:
    """
    LSTM Autoencoder anomaly detector for sequence-based intrusion detection.
    Model B in the Phase 2 ablation study.

    Trains on windows of W consecutive benign flows and detects anomalies via
    reconstruction error:  score(X) = mean ||X - decode(encode(X))||²

    Parameters
    ----------
    window_size : int
        Flows per sequence window (default 50).
    latent_dim : int
        Bottleneck dimension — 32 gives 53× compression of a (50,34) window.
    dropout_rate : float
        Dropout applied after each LSTM encoder/decoder layer.
    """

    def __init__(
        self,
        window_size: int = 50,
        latent_dim: int = 32,
        dropout_rate: float = 0.2,
    ) -> None:
        self.window_size   = window_size
        self.latent_dim    = latent_dim
        self.dropout_rate  = dropout_rate
        self.model         = None
        self.threshold     = None
        self._feature_dim  = None

    # ------------------------------------------------------------------
    def fit(
        self,
        X_train_seq: np.ndarray,
        X_val_seq: Optional[np.ndarray] = None,
        epochs: int = 100,
        batch_size: int = 256,
        patience: int = 10,
    ) -> "LSTMAEDetector":
        """
        Train the LSTM autoencoder on benign-only sequences.

        Parameters
        ----------
        X_train_seq : (n_windows, window_size, n_features)
            Benign sliding-window sequences.
        X_val_seq : optional validation sequences for early stopping.
        """
        import tensorflow as tf
        from tensorflow.keras.models import Model as KModel
        from tensorflow.keras.layers import (
            Input, LSTM, Dense, Dropout, RepeatVector, TimeDistributed,
        )
        from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau

        tf.random.set_seed(42)
        self._feature_dim = X_train_seq.shape[2]
        W = self.window_size
        F = self._feature_dim
        L = self.latent_dim
        D = self.dropout_rate

        inp  = Input(shape=(W, F), name="input")
        x    = LSTM(128, return_sequences=True,  name="enc_lstm1")(inp)
        x    = Dropout(D, name="enc_drop1")(x)
        x    = LSTM(64,  return_sequences=False, name="enc_lstm2")(x)
        x    = Dropout(D, name="enc_drop2")(x)
        z    = Dense(L, activation="relu", name="latent")(x)
        x    = RepeatVector(W, name="repeat")(z)
        x    = LSTM(64,  return_sequences=True,  name="dec_lstm1")(x)
        x    = Dropout(D, name="dec_drop1")(x)
        x    = LSTM(128, return_sequences=True,  name="dec_lstm2")(x)
        x    = Dropout(D, name="dec_drop2")(x)
        out  = TimeDistributed(Dense(F, activation="linear"), name="output")(x)

        self.model = KModel(inp, out, name="lstm_autoencoder")
        self.model.compile(
            optimizer=tf.keras.optimizers.Adam(1e-3, clipnorm=1.0),
            loss="mse",
        )

        callbacks = [
            EarlyStopping(
                monitor="val_loss", patience=patience,
                restore_best_weights=True, verbose=0,
            ),
            ReduceLROnPlateau(
                monitor="val_loss", factor=0.5, patience=5, min_lr=1e-6, verbose=0,
            ),
        ]
        val_data = (X_val_seq, X_val_seq) if X_val_seq is not None else None
        self.model.fit(
            X_train_seq, X_train_seq,
            validation_data=val_data,
            epochs=epochs,
            batch_size=batch_size,
            callbacks=callbacks,
            verbose=0,
        )
        return self

    # ------------------------------------------------------------------
    def score(self, X_seq: np.ndarray) -> np.ndarray:
        """
        Per-sequence anomaly score = mean MSE over all timesteps and features.

        score(X) = (1 / W*F) * Σ ||x_t - x̂_t||²

        Higher scores indicate greater anomaly likelihood.

        Parameters
        ----------
        X_seq : (n_windows, window_size, n_features)
        """
        if self.model is None:
            raise RuntimeError("Call fit() or load() before score().")
        X_hat = self.model.predict(X_seq, batch_size=512, verbose=0)
        return np.mean(np.square(X_seq - X_hat), axis=(1, 2))

    # ------------------------------------------------------------------
    def predict(self, X_seq: np.ndarray) -> np.ndarray:
        """
        Binary predictions using the fitted threshold.

        Returns
        -------
        np.ndarray of int  — 1 = anomaly, 0 = benign.
        """
        if self.threshold is None:
            raise RuntimeError("Set threshold via set_threshold() before predict().")
        return (self.score(X_seq) > self.threshold).astype(int)

    # ------------------------------------------------------------------
    def set_threshold(
        self,
        X_val_benign_seq: np.ndarray,
        percentile: int = 95,
    ) -> float:
        """
        Calibrate decision threshold from validation benign sequences.

        Uses the ``percentile``-th percentile of benign reconstruction errors,
        ensuring the threshold is not tuned on the test set.
        """
        val_scores    = self.score(X_val_benign_seq)
        self.threshold = float(np.percentile(val_scores, percentile))
        return self.threshold

    # ------------------------------------------------------------------
    def evaluate(
        self,
        X_seq: np.ndarray,
        y_seq: np.ndarray,
    ) -> Dict[str, float]:
        """
        Full evaluation metrics on sequence-labelled data.

        Parameters
        ----------
        X_seq : (n_windows, window_size, n_features)
        y_seq : (n_windows,) binary — 1 = anomalous window, 0 = benign.
        """
        scores = self.score(X_seq)
        y_pred = (scores > self.threshold).astype(int)
        return {
            "precision": float(precision_score(y_seq, y_pred, zero_division=0)),
            "recall":    float(recall_score(y_seq, y_pred, zero_division=0)),
            "f1":        float(f1_score(y_seq, y_pred, zero_division=0)),
            "auc":       float(roc_auc_score(y_seq, scores)),
            "threshold": self.threshold,
        }

    # ------------------------------------------------------------------
    def save(self, path: Union[str, pathlib.Path]) -> None:
        """Save Keras model, threshold, and hyperparameters."""
        path = pathlib.Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.model.save(str(path) + "_model.keras")
        np.save(str(path) + "_threshold.npy", np.array(self.threshold))
        joblib.dump(
            {
                "window_size":   self.window_size,
                "latent_dim":    self.latent_dim,
                "dropout_rate":  self.dropout_rate,
                "_feature_dim":  self._feature_dim,
            },
            str(path) + "_params.pkl",
        )
        print(f"LSTMAEDetector saved → {path}[_model.keras / _threshold.npy / _params.pkl]")

    # ------------------------------------------------------------------
    @classmethod
    def load(cls, path: Union[str, pathlib.Path]) -> "LSTMAEDetector":
        """Load a previously saved LSTMAEDetector."""
        import tensorflow as tf

        path   = pathlib.Path(path)
        params = joblib.load(str(path) + "_params.pkl")
        obj    = cls(
            window_size  = params["window_size"],
            latent_dim   = params["latent_dim"],
            dropout_rate = params["dropout_rate"],
        )
        obj._feature_dim = params["_feature_dim"]
        obj.model        = tf.keras.models.load_model(str(path) + "_model.keras")
        obj.threshold    = float(np.load(str(path) + "_threshold.npy"))
        return obj


# ──────────────────────────────────────────────────────────────────────────────
# Hybrid Detector  (Model C — Phase 3)
# ──────────────────────────────────────────────────────────────────────────────

class HybridDetector:
    """
    Hybrid anomaly detector combining GMM (Model A) and LSTM-AE (Model B).
    Model C in the Phase 3 ablation study.

    Architecture
    ------------
    For each flow x_i:
      1. GMM score   : s_GMM  = -log p_GMM(x_i)          (flow-level, no context)
      2. LSTM score  : s_LSTM = mean MSE(window containing x_i)  (temporal context)
      3. Both normalised to [0,1] using val-set min/max.
      4. Meta-learner: P(attack | s_GMM, s_LSTM) via RF or logistic regression.

    The meta-learner is trained on val benign (y=0) + a stratified fraction of
    the temporal test set.  Threshold = 0.5 on predicted probability.

    Parameters
    ----------
    gmm_model : sklearn GaussianMixture (already fitted)
    lstm_ae_model : tf.keras.Model (already fitted LSTM-AE)
    meta_learner : fitted sklearn estimator or None
        If None, uses weighted average with alpha.
    alpha : float
        GMM weight in weighted average (used when meta_learner is None).
    window_size : int
        Sliding window length for LSTM-AE sequences.
    stride : int
        Stride for test-set sequences (default 25 for memory efficiency).
    val_gmm_min, val_gmm_max : float
        Min/max of GMM neg-LL on validation benign flows (for normalisation).
    val_lstm_min, val_lstm_max : float
        Min/max of LSTM MSE on validation benign sequences.
    """

    def __init__(
        self,
        gmm_model,
        lstm_ae_model,
        meta_learner=None,
        alpha: float = 0.7,
        window_size: int = 50,
        stride: int = 25,
        val_gmm_min: float = 0.0,
        val_gmm_max: float = 1.0,
        val_lstm_min: float = 0.0,
        val_lstm_max: float = 1.0,
    ) -> None:
        self.gmm_model     = gmm_model
        self.lstm_ae_model = lstm_ae_model
        self.meta_learner  = meta_learner
        self.alpha         = alpha
        self.window_size   = window_size
        self.stride        = stride
        self.val_gmm_min   = val_gmm_min
        self.val_gmm_max   = val_gmm_max
        self.val_lstm_min  = val_lstm_min
        self.val_lstm_max  = val_lstm_max

    # ------------------------------------------------------------------
    def _gmm_scores(self, X: np.ndarray) -> np.ndarray:
        raw = -self.gmm_model.score_samples(X)
        return np.clip(
            (raw - self.val_gmm_min) / (self.val_gmm_max - self.val_gmm_min + 1e-8),
            0.0, 1.0,
        )

    def _lstm_scores(self, X: np.ndarray) -> np.ndarray:
        n = len(X)
        W = self.window_size
        s = self.stride

        starts = range(0, max(1, n - W + 1), s)
        seq_batch = np.array(
            [X[t : t + W] for t in starts if t + W <= n], dtype=np.float32
        )
        if len(seq_batch) == 0:
            return np.zeros(n)

        recon  = self.lstm_ae_model.predict(seq_batch, batch_size=256, verbose=0)
        w_mse  = np.mean(np.square(seq_batch - recon), axis=(1, 2))

        flow_sum = np.zeros(n)
        flow_cnt = np.zeros(n, dtype=np.int32)
        for i, t in enumerate(starts):
            if i >= len(w_mse):
                break
            flow_sum[t : t + W] += w_mse[i]
            flow_cnt[t : t + W] += 1

        flow_raw = np.where(flow_cnt > 0, flow_sum / flow_cnt, 0.0)
        return np.clip(
            (flow_raw - self.val_lstm_min) / (self.val_lstm_max - self.val_lstm_min + 1e-8),
            0.0, 1.0,
        )

    # ------------------------------------------------------------------
    def score(self, X: np.ndarray) -> np.ndarray:
        """
        Return hybrid anomaly scores in [0, 1].

        If a meta_learner is fitted, returns P(attack | s_GMM, s_LSTM).
        Otherwise returns alpha * s_GMM + (1 - alpha) * s_LSTM.

        Parameters
        ----------
        X : (n_flows, n_features) — raw preprocessed flow features.
        """
        s_gmm  = self._gmm_scores(X)
        s_lstm = self._lstm_scores(X)

        if self.meta_learner is not None:
            X_meta = np.column_stack([s_gmm, s_lstm])
            return self.meta_learner.predict_proba(X_meta)[:, 1]
        return self.alpha * s_gmm + (1.0 - self.alpha) * s_lstm

    # ------------------------------------------------------------------
    def predict(self, X: np.ndarray, threshold: float = 0.5) -> np.ndarray:
        """
        Binary predictions: 1 = attack, 0 = benign.

        Parameters
        ----------
        X : (n_flows, n_features)
        threshold : decision boundary on the hybrid score (default 0.5).
        """
        return (self.score(X) >= threshold).astype(int)

    # ------------------------------------------------------------------
    def evaluate(
        self, X: np.ndarray, y: np.ndarray, threshold: float = 0.5
    ) -> Dict[str, float]:
        """
        Compute evaluation metrics on labelled flow data.

        Parameters
        ----------
        X : (n_flows, n_features)
        y : (n_flows,) binary — 1 = attack, 0 = benign.
        threshold : float, decision threshold (default 0.5).

        Returns
        -------
        dict with precision, recall, f1, auc, fpr, fnr.
        """
        scores = self.score(X)
        y_pred = (scores >= threshold).astype(int)

        cm = confusion_matrix(y, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
        n_neg = tn + fp
        n_pos = tp + fn

        return {
            "precision": float(precision_score(y, y_pred, zero_division=0)),
            "recall":    float(recall_score(y, y_pred, zero_division=0)),
            "f1":        float(f1_score(y, y_pred, zero_division=0)),
            "auc":       float(roc_auc_score(y, scores)),
            "fpr":       fp / n_neg if n_neg > 0 else 0.0,
            "fnr":       fn / n_pos if n_pos > 0 else 0.0,
            "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
        }

    # ------------------------------------------------------------------
    def save(self, path: Union[str, pathlib.Path]) -> None:
        """
        Persist the HybridDetector to disk.

        Saves: {path}_hybrid.pkl  (this object, excluding Keras model)
               {path}_meta.pkl    (meta-learner, if not None)
        The GMM is already saved separately by GMMDetector.save().
        The LSTM-AE Keras model should be saved via LSTMAEDetector.save().
        """
        path = pathlib.Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        # Save meta-learner separately so it can be loaded without Keras/GMM
        if self.meta_learner is not None:
            joblib.dump(self.meta_learner, str(path) + "_meta.pkl")

        # Save scalars + config (not the heavy Keras / GMM objects)
        params = {
            "alpha":        self.alpha,
            "window_size":  self.window_size,
            "stride":       self.stride,
            "val_gmm_min":  self.val_gmm_min,
            "val_gmm_max":  self.val_gmm_max,
            "val_lstm_min": self.val_lstm_min,
            "val_lstm_max": self.val_lstm_max,
        }
        joblib.dump(params, str(path) + "_hybrid.pkl")
        print(f"HybridDetector saved → {path}[_hybrid.pkl / _meta.pkl]")

    # ------------------------------------------------------------------
    @classmethod
    def load(
        cls,
        path: Union[str, pathlib.Path],
        gmm_model,
        lstm_ae_model,
    ) -> "HybridDetector":
        """
        Load a persisted HybridDetector.

        Parameters
        ----------
        path : str or Path — same prefix used in save().
        gmm_model : fitted GaussianMixture (load separately).
        lstm_ae_model : fitted Keras model (load separately).
        """
        path   = pathlib.Path(path)
        params = joblib.load(str(path) + "_hybrid.pkl")

        meta_path = pathlib.Path(str(path) + "_meta.pkl")
        meta = joblib.load(meta_path) if meta_path.exists() else None

        obj = cls(gmm_model=gmm_model, lstm_ae_model=lstm_ae_model,
                  meta_learner=meta, **params)
        return obj


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
