"""
src/evaluate.py
===============
Standalone evaluation utilities for the Adaptive Cyber-Physical Security project.

Functions
---------
compute_metrics         : Full metrics dict from predictions + scores.
plot_roc_curve          : ROC curve figure saved to disk.
plot_confusion_matrix   : Confusion matrix heatmap saved to disk.
plot_score_distribution : Overlapping anomaly score histograms.
per_class_detection_rate: Per-attack-type detection rate DataFrame.
generate_report         : Plain-text summary saved to disk.
"""

from __future__ import annotations

import pathlib
from typing import Dict, List, Optional, Union

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.metrics import (
    auc,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)


# ──────────────────────────────────────────────────────────────────────────────

def compute_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_scores: np.ndarray,
) -> Dict[str, float]:
    """
    Compute a comprehensive set of binary classification metrics.

    Parameters
    ----------
    y_true : np.ndarray of int, shape (n_samples,)
        Ground-truth binary labels: 1 = attack, 0 = benign.
    y_pred : np.ndarray of int, shape (n_samples,)
        Binary predictions.
    y_scores : np.ndarray of float, shape (n_samples,)
        Continuous anomaly scores (higher = more anomalous).

    Returns
    -------
    dict with keys:
        precision, recall, f1, auc_roc, tp, fp, tn, fn, fpr, fnr, accuracy
    """
    precision = float(precision_score(y_true, y_pred, zero_division=0))
    recall    = float(recall_score(y_true, y_pred, zero_division=0))
    f1        = float(f1_score(y_true, y_pred, zero_division=0))
    try:
        auc_roc = float(roc_auc_score(y_true, y_scores))
    except ValueError:
        auc_roc = float("nan")

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)

    n_neg = int(tn) + int(fp)
    n_pos = int(tp) + int(fn)
    fpr = int(fp) / n_neg if n_neg > 0 else 0.0
    fnr = int(fn) / n_pos if n_pos > 0 else 0.0
    accuracy = (int(tp) + int(tn)) / len(y_true) if len(y_true) > 0 else 0.0

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "auc_roc": auc_roc,
        "accuracy": accuracy,
        "tp": int(tp),
        "fp": int(fp),
        "tn": int(tn),
        "fn": int(fn),
        "fpr": fpr,
        "fnr": fnr,
    }


def plot_roc_curve(
    y_true: np.ndarray,
    y_scores: np.ndarray,
    label: str = "Model",
    save_path: Optional[Union[str, pathlib.Path]] = None,
) -> plt.Figure:
    """
    Plot and optionally save a ROC curve.

    Parameters
    ----------
    y_true : np.ndarray
        Binary ground-truth labels.
    y_scores : np.ndarray
        Continuous anomaly scores (higher = more anomalous).
    label : str
        Legend label for the curve.
    save_path : str or Path, optional
        If provided, saves the figure here.

    Returns
    -------
    matplotlib.figure.Figure
    """
    fpr, tpr, _ = roc_curve(y_true, y_scores)
    roc_auc = auc(fpr, tpr)

    fig, ax = plt.subplots(figsize=(7, 6))
    ax.plot(fpr, tpr, lw=2, color="#3498DB",
            label=f"{label}  (AUC = {roc_auc:.4f})")
    ax.plot([0, 1], [0, 1], "k--", lw=1, alpha=0.5, label="Random classifier")
    ax.set_xlabel("False Positive Rate", fontsize=12)
    ax.set_ylabel("True Positive Rate", fontsize=12)
    ax.set_title("Receiver Operating Characteristic (ROC) Curve", fontsize=13)
    ax.legend(fontsize=11)
    ax.grid(alpha=0.3)
    ax.set_xlim([0, 1])
    ax.set_ylim([0, 1.02])
    fig.tight_layout()

    if save_path is not None:
        _save(fig, save_path)
    return fig


def plot_confusion_matrix(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    save_path: Optional[Union[str, pathlib.Path]] = None,
    labels: List[str] = None,
) -> plt.Figure:
    """
    Plot and optionally save a confusion matrix heatmap.

    Parameters
    ----------
    y_true : np.ndarray
    y_pred : np.ndarray
    save_path : str or Path, optional
    labels : list[str], optional
        Class names for axis ticks (default ['Benign', 'Attack']).

    Returns
    -------
    matplotlib.figure.Figure
    """
    if labels is None:
        labels = ["Benign", "Attack"]

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    cm_pct = cm.astype(float) / cm.sum(axis=1, keepdims=True) * 100

    fig, ax = plt.subplots(figsize=(6, 5))
    sns.heatmap(
        cm_pct, annot=True, fmt=".1f", cmap="Blues",
        xticklabels=[f"Pred {l}" for l in labels],
        yticklabels=[f"True {l}" for l in labels],
        ax=ax, linewidths=0.5, cbar_kws={"label": "% of true class"},
    )
    # Add raw counts as secondary annotation
    for i in range(2):
        for j in range(2):
            ax.text(j + 0.5, i + 0.72, f"(n={cm[i,j]:,})",
                    ha="center", va="center", fontsize=8, color="grey")
    ax.set_title("Confusion Matrix", fontsize=13)
    ax.set_xlabel("Predicted Label", fontsize=11)
    ax.set_ylabel("True Label", fontsize=11)
    fig.tight_layout()

    if save_path is not None:
        _save(fig, save_path)
    return fig


def plot_score_distribution(
    scores_benign: np.ndarray,
    scores_attack: np.ndarray,
    save_path: Optional[Union[str, pathlib.Path]] = None,
    threshold: Optional[float] = None,
    model_name: str = "Model",
) -> plt.Figure:
    """
    Plot overlapping histograms of anomaly scores for benign and attack flows.

    Parameters
    ----------
    scores_benign : np.ndarray
        Anomaly scores for benign test samples.
    scores_attack : np.ndarray
        Anomaly scores for attack test samples.
    save_path : str or Path, optional
    threshold : float, optional
        If provided, draws a vertical decision threshold line.
    model_name : str
        Used in the plot title.

    Returns
    -------
    matplotlib.figure.Figure
    """
    fig, ax = plt.subplots(figsize=(9, 5))

    ax.hist(scores_benign, bins=80, density=True, alpha=0.55,
            color="#27AE60", label="Benign traffic")
    ax.hist(scores_attack, bins=80, density=True, alpha=0.55,
            color="#E74C3C", label="Attack traffic")

    if threshold is not None:
        ax.axvline(threshold, color="#2C3E50", lw=2, linestyle="--",
                   label=f"Decision threshold τ = {threshold:.2f}")

    ax.set_xlabel("Anomaly Score  (−log p(x))", fontsize=12)
    ax.set_ylabel("Density", fontsize=12)
    ax.set_title(f"{model_name} — Anomaly Score Distribution", fontsize=13)
    ax.legend(fontsize=11)
    ax.grid(alpha=0.3)
    fig.tight_layout()

    if save_path is not None:
        _save(fig, save_path)
    return fig


def per_class_detection_rate(
    y_true_multiclass: np.ndarray,
    y_pred: np.ndarray,
) -> pd.DataFrame:
    """
    Compute per-attack-type detection rates.

    Parameters
    ----------
    y_true_multiclass : np.ndarray of str
        Multi-class ground-truth labels (e.g., 'BENIGN', 'DDoS', 'DoS Hulk').
    y_pred : np.ndarray of int
        Binary predictions from the anomaly detector (1=attack detected).

    Returns
    -------
    pd.DataFrame with columns:
        Attack Type, Total, Detected, Missed, Detection Rate (%)
    """
    attack_types = sorted(
        set(y_true_multiclass) - {"BENIGN", "benign", "Benign", "NORMAL"}
    )
    rows = []
    for attack in attack_types:
        mask = y_true_multiclass == attack
        total    = int(mask.sum())
        detected = int(y_pred[mask].sum())
        missed   = total - detected
        rate     = detected / total * 100 if total > 0 else 0.0
        rows.append({
            "Attack Type": attack,
            "Total": total,
            "Detected": detected,
            "Missed": missed,
            "Detection Rate (%)": f"{rate:.1f}%",
        })
    return pd.DataFrame(rows).sort_values("Total", ascending=False)


def generate_report(
    model_name: str,
    metrics_dict: Dict[str, float],
    save_path: Union[str, pathlib.Path],
    extra_lines: Optional[List[str]] = None,
) -> None:
    """
    Save a plain-text summary of model evaluation metrics.

    Parameters
    ----------
    model_name : str
    metrics_dict : dict
        Output of compute_metrics().
    save_path : str or Path
        Path to the .txt file to create.
    extra_lines : list[str], optional
        Additional lines to append at the end of the report.
    """
    save_path = pathlib.Path(save_path)
    save_path.parent.mkdir(parents=True, exist_ok=True)

    sep = "=" * 55
    lines = [
        sep,
        f"  EVALUATION REPORT — {model_name}",
        sep,
        f"  Precision   : {metrics_dict.get('precision', 0):.4f}",
        f"  Recall      : {metrics_dict.get('recall', 0):.4f}",
        f"  F1-Score    : {metrics_dict.get('f1', 0):.4f}",
        f"  AUC-ROC     : {metrics_dict.get('auc_roc', 0):.4f}",
        f"  Accuracy    : {metrics_dict.get('accuracy', 0):.4f}",
        "",
        f"  True  Positives : {metrics_dict.get('tp', 0):>10,}",
        f"  False Positives : {metrics_dict.get('fp', 0):>10,}",
        f"  True  Negatives : {metrics_dict.get('tn', 0):>10,}",
        f"  False Negatives : {metrics_dict.get('fn', 0):>10,}",
        "",
        f"  False Positive Rate (FPR) : {metrics_dict.get('fpr', 0):.4f}",
        f"  False Negative Rate (FNR) : {metrics_dict.get('fnr', 0):.4f}",
        sep,
    ]
    if extra_lines:
        lines += extra_lines

    report_text = "\n".join(lines)
    save_path.write_text(report_text)
    print(f"Report saved → {save_path}")


# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────────

def _save(fig: plt.Figure, path: Union[str, pathlib.Path]) -> None:
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved → {path}")


# ──────────────────────────────────────────────────────────────────────────────
# Smoke test
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import pathlib

    ROOT = pathlib.Path(__file__).parent.parent
    prep = ROOT / "outputs" / "preprocessing"
    out  = ROOT / "outputs" / "eval_smoke"

    print("Loading data …")
    y_test    = np.load(prep / "y_test.npy")
    y_test_mc = np.load(prep / "y_test_multiclass.npy", allow_pickle=True)
    X_test    = np.load(prep / "X_test.npy")

    # Fake predictions for smoke test
    rng = np.random.default_rng(0)
    y_pred   = (rng.random(len(y_test)) > 0.5).astype(int)
    y_scores = rng.random(len(y_test))

    metrics = compute_metrics(y_test, y_pred, y_scores)
    print("Metrics:", metrics)

    plot_roc_curve(y_test, y_scores, label="Smoke Test",
                   save_path=out / "roc.png")
    plot_confusion_matrix(y_test, y_pred,
                          save_path=out / "cm.png")
    plot_score_distribution(
        y_scores[y_test == 0], y_scores[y_test == 1],
        save_path=out / "score_dist.png",
        model_name="Smoke Test"
    )
    dr = per_class_detection_rate(y_test_mc, y_pred)
    print(dr.head())

    generate_report("Smoke Test", metrics, out / "report.txt")
    print("Smoke test passed.")
