"""
src/features.py
===============
Feature engineering pipeline for the Adaptive Cyber-Physical Security project.

Implements the FeatureEngineer class that replicates every preprocessing step
from Stage 2 (stage2_preprocessing.ipynb) as a reusable, fit/transform interface.

All fit parameters are estimated from benign training data only.  Applying
transform() to any data set is safe — no information from test/attack data
leaks into the preprocessing statistics.

Usage
-----
>>> from src.features import FeatureEngineer
>>> fe = FeatureEngineer()
>>> X_train_processed = fe.fit_transform(X_benign_raw)
>>> X_test_processed  = fe.transform(X_test_raw)
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from typing import List, Optional
import warnings


# ─── Constants ────────────────────────────────────────────────────────────────
IQR_LOWER_QUANTILE = 0.01
IQR_UPPER_QUANTILE = 0.99
SKEWNESS_THRESHOLD = 1.0          # abs skew above this triggers log transform
CORRELATION_THRESHOLD = 0.95      # drop one of any pair with |corr| > threshold
LOG_SHIFT = 1.0                   # log(1 + shift + x) avoids log(0)


class FeatureEngineer:
    """
    Fit/transform pipeline for network flow anomaly detection.

    Parameters
    ----------
    iqr_lower : float
        Lower quantile for IQR-based outlier capping (default 0.01).
    iqr_upper : float
        Upper quantile for IQR-based outlier capping (default 0.99).
    skew_threshold : float
        Absolute skewness threshold above which log transform is applied
        (default 1.0).
    corr_threshold : float
        Pearson |correlation| threshold for dropping redundant features
        (default 0.95).

    Attributes
    ----------
    is_fitted_ : bool
        True after fit() has been called.
    feature_names_ : list[str]
        Final ordered feature names after all engineering steps.
    """

    def __init__(
        self,
        iqr_lower: float = IQR_LOWER_QUANTILE,
        iqr_upper: float = IQR_UPPER_QUANTILE,
        skew_threshold: float = SKEWNESS_THRESHOLD,
        corr_threshold: float = CORRELATION_THRESHOLD,
    ) -> None:
        self.iqr_lower = iqr_lower
        self.iqr_upper = iqr_upper
        self.skew_threshold = skew_threshold
        self.corr_threshold = corr_threshold

        # Learned from benign train
        self._lower_caps: Optional[np.ndarray] = None
        self._upper_caps: Optional[np.ndarray] = None
        self._log_mask: Optional[np.ndarray] = None
        self._robust_median: Optional[np.ndarray] = None
        self._robust_iqr: Optional[np.ndarray] = None
        self._drop_columns: Optional[List[str]] = None
        self._kept_columns: Optional[List[str]] = None
        self._raw_feature_names: Optional[List[str]] = None
        self.feature_names_: Optional[List[str]] = None
        self.is_fitted_: bool = False

    # ──────────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────────

    def fit(self, X_benign: pd.DataFrame) -> "FeatureEngineer":
        """
        Learn all preprocessing statistics from benign training data.

        Steps performed (all fit on X_benign only):
        1. Drop infinite / NaN values.
        2. Compute IQR quantile caps for outlier capping.
        3. Identify skewed features for log transform.
        4. Engineer ratio and timing interaction features.
        5. Fit RobustScaler statistics (median, IQR).
        6. Identify highly correlated feature pairs to drop.

        Parameters
        ----------
        X_benign : pd.DataFrame
            Raw feature matrix from benign training flows.

        Returns
        -------
        self
        """
        X = X_benign.copy()
        self._raw_feature_names = list(X.columns)

        # Step 1: Remove infinities → NaN, then drop NaN rows for fitting
        X = X.replace([np.inf, -np.inf], np.nan)
        X = X.dropna()

        # Step 2: IQR outlier capping boundaries
        self._lower_caps = X.quantile(self.iqr_lower).values
        self._upper_caps = X.quantile(self.iqr_upper).values

        # Apply caps before computing downstream statistics
        X_capped = self._apply_caps(X)

        # Step 3: Identify skewed features (log-transform candidates)
        skewness = X_capped.skew()
        self._log_mask = (np.abs(skewness.values) > self.skew_threshold)

        # Step 4: Engineer interaction features
        X_eng = self._engineer_features(X_capped)

        # Step 5: Log transform
        X_log = self._apply_log(X_eng)

        # Step 5: RobustScaler — median and IQR from benign train
        self._robust_median = np.median(X_log.values, axis=0)
        q75 = np.percentile(X_log.values, 75, axis=0)
        q25 = np.percentile(X_log.values, 25, axis=0)
        self._robust_iqr = np.where((q75 - q25) == 0, 1.0, q75 - q25)

        X_scaled = (X_log.values - self._robust_median) / self._robust_iqr
        X_scaled_df = pd.DataFrame(X_scaled, columns=X_log.columns)

        # Step 6: Correlation-based feature removal
        self._drop_columns, self._kept_columns = self._find_correlated_drops(X_scaled_df)
        self.feature_names_ = self._kept_columns
        self.is_fitted_ = True
        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray:
        """
        Apply the fitted preprocessing pipeline to any data split.

        Parameters
        ----------
        X : pd.DataFrame
            Raw feature matrix. Must have the same column names as the
            data passed to fit().

        Returns
        -------
        np.ndarray
            Processed feature matrix of shape (n_samples, n_features_out).
        """
        self._check_fitted()
        X = X.copy()

        # Step 1: Inf → NaN fill (use column median rather than dropping rows)
        X = X.replace([np.inf, -np.inf], np.nan)
        for col in X.columns:
            if X[col].isna().any():
                X[col] = X[col].fillna(X[col].median())

        # Step 2: Outlier capping
        X_capped = self._apply_caps(X)

        # Step 3 & 4: Engineer features then log-transform
        X_eng = self._engineer_features(X_capped)
        X_log = self._apply_log(X_eng)

        # Step 5: RobustScaler with train parameters
        X_scaled = (X_log.values - self._robust_median) / self._robust_iqr

        # Step 6: Drop correlated columns
        X_scaled_df = pd.DataFrame(X_scaled, columns=X_log.columns)
        X_final = X_scaled_df[self._kept_columns].values
        return X_final

    def fit_transform(self, X_benign: pd.DataFrame) -> np.ndarray:
        """
        Fit on benign training data and immediately transform it.

        Parameters
        ----------
        X_benign : pd.DataFrame

        Returns
        -------
        np.ndarray
        """
        return self.fit(X_benign).transform(X_benign)

    def get_feature_names(self) -> List[str]:
        """
        Return the ordered list of output feature names.

        Returns
        -------
        list[str]
            Feature names after all engineering and selection steps.
        """
        self._check_fitted()
        return list(self.feature_names_)

    # ──────────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _apply_caps(self, X: pd.DataFrame) -> pd.DataFrame:
        """Clip each column to [lower_cap, upper_cap] learned from training."""
        X_capped = X.copy()
        for i, col in enumerate(self._raw_feature_names):
            if col in X_capped.columns:
                col_idx = list(self._raw_feature_names).index(col)
                X_capped[col] = X_capped[col].clip(
                    self._lower_caps[col_idx],
                    self._upper_caps[col_idx]
                )
        return X_capped

    def _engineer_features(self, X: pd.DataFrame) -> pd.DataFrame:
        """
        Construct domain-informed interaction features.

        Features added (prefixed with ``feat_``):
        - ``feat_fwd_bwd_pkt_ratio``:
            Forward/backward packet asymmetry.  Scanning and DoS flows are
            typically unidirectional.
            Formula: Fwd_Pkts / (Bwd_Pkts + 1)
        - ``feat_fwd_bwd_byte_ratio``:
            Forward/backward byte asymmetry (exfiltration indicator).
            Formula: Subflow_Fwd_Bytes / (Total_Length_Bwd_Pkts + 1)
        - ``feat_payload_ratio``:
            Fraction of packets that carry a payload.
            Formula: Avg_Pkt_Size / (Max_Pkt_Len + 1)
        - ``feat_burst_intensity``:
            Packet burst indicator — high variance relative to mean IAT.
            Formula: Flow_IAT_Std / (Flow_IAT_Mean + 1)
        - ``feat_byte_entropy_approx``:
            Proxy for payload entropy using variance of packet sizes.
            Formula: Pkt_Len_Var / (Avg_Pkt_Size^2 + 1)
        """
        X = X.copy()

        # Helper: safe column access
        def col(name: str) -> pd.Series:
            if name in X.columns:
                return X[name].fillna(0)
            return pd.Series(np.zeros(len(X)), index=X.index)

        X["feat_fwd_bwd_pkt_ratio"] = col("Total Fwd Packets") / (
            col("Total Backward Packets") + 1
        )
        X["feat_fwd_bwd_byte_ratio"] = col("Subflow Fwd Bytes") / (
            col("Total Length of Bwd Packets") + 1
        )
        X["feat_payload_ratio"] = col("Average Packet Size") / (
            col("Max Packet Length") + 1
        )
        X["feat_burst_intensity"] = col("Flow IAT Std") / (
            col("Flow IAT Mean") + 1
        )
        X["feat_byte_entropy_approx"] = col("Packet Length Variance") / (
            col("Average Packet Size") ** 2 + 1
        )
        return X

    def _apply_log(self, X: pd.DataFrame) -> pd.DataFrame:
        """
        Apply log(1 + x) to columns whose skewness exceeds the threshold.

        Uses the ``_log_mask`` array learned during fit.  Columns added
        during _engineer_features (starting with ``feat_``) are always
        log-transformed because interaction ratios tend to be heavy-tailed.
        """
        X = X.copy()
        base_cols = self._raw_feature_names
        eng_cols = [c for c in X.columns if c.startswith("feat_")]

        for i, col in enumerate(base_cols):
            if col in X.columns and self._log_mask[i]:
                X[col] = np.log1p(np.maximum(X[col], 0))

        for col in eng_cols:
            X[col] = np.log1p(np.maximum(X[col], 0))

        return X

    def _find_correlated_drops(
        self, X: pd.DataFrame
    ) -> tuple[List[str], List[str]]:
        """
        Identify one column from each highly correlated pair to drop.

        Returns
        -------
        drop_cols : list[str]
        kept_cols : list[str]
        """
        corr = X.corr().abs()
        upper = corr.where(np.triu(np.ones(corr.shape), k=1).astype(bool))
        drop = [col for col in upper.columns if any(upper[col] > self.corr_threshold)]
        kept = [c for c in X.columns if c not in drop]
        return drop, kept

    def _check_fitted(self) -> None:
        if not self.is_fitted_:
            raise RuntimeError(
                "FeatureEngineer is not fitted. Call fit() or fit_transform() first."
            )


# ──────────────────────────────────────────────────────────────────────────────
# Smoke test
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import os
    import pathlib

    ROOT = pathlib.Path(__file__).parent.parent
    prep_dir = ROOT / "outputs" / "preprocessing"

    print("Loading preprocessed arrays …")
    X_train = np.load(prep_dir / "X_train.npy")
    X_test  = np.load(prep_dir / "X_test.npy")
    feat_txt = prep_dir / "feature_names.txt"
    with open(feat_txt) as f:
        feature_names = [ln.strip() for ln in f if ln.strip()]

    print(f"  X_train : {X_train.shape}")
    print(f"  X_test  : {X_test.shape}")
    print(f"  Features: {len(feature_names)}")

    # Wrap as DataFrame for FeatureEngineer
    X_train_df = pd.DataFrame(X_train, columns=feature_names)
    X_test_df  = pd.DataFrame(X_test,  columns=feature_names)

    fe = FeatureEngineer()
    print("\nFitting FeatureEngineer on X_train …")
    X_train_out = fe.fit_transform(X_train_df)
    print(f"  Output shape : {X_train_out.shape}")
    print(f"  Feature names: {fe.get_feature_names()[:5]} …")

    X_test_out = fe.transform(X_test_df)
    print(f"  Test shape   : {X_test_out.shape}")
    print("\nSmoke test passed.")
