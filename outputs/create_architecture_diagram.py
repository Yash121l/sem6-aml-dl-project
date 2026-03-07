"""
Stage 4 — Architecture Diagram Generator
Adaptive Cyber-Physical Security · Phase 1

Creates two figures:
  1. Full pipeline diagram  → outputs/architecture_diagram_phase1.png / .pdf
  2. Ablation overview      → outputs/ablation_overview.png
"""

import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import matplotlib.patheffects as pe

# ─── COLORS ───────────────────────────────────────────────────────────────────
C_DATA    = "#AED6F1"   # light blue   – raw data / dataset
C_TRAIN   = "#A9DFBF"   # light green  – benign / training path
C_TEST    = "#FAD7A0"   # light orange – mixed / test path
C_PIPE    = "#D7BDE2"   # light purple – preprocessing
C_MODEL   = "#C9B1FF"   # medium purple– model
C_EVAL    = "#FDFEFE"   # white        – evaluation / results
C_FUTURE  = "#D5D8DC"   # light grey   – future phases
C_BORDER  = "#2C3E50"   # dark         – box borders
C_LEAK    = "#E74C3C"   # red          – leakage boundary annotation
C_ARROW   = "#566573"   # grey-blue    – arrows

OUT_DIR = os.path.dirname(os.path.abspath(__file__))


def draw_box(ax, x, y, w, h, text, color, fontsize=9,
             bold=False, subtext=None, sub_fontsize=8,
             linestyle="solid", alpha=1.0, text_color="black"):
    """Draw a rounded rectangle with main + optional sub-text."""
    bbox = FancyBboxPatch(
        (x - w / 2, y - h / 2), w, h,
        boxstyle="round,pad=0.03",
        facecolor=color, edgecolor=C_BORDER,
        linewidth=1.4, linestyle=linestyle, alpha=alpha, zorder=3
    )
    ax.add_patch(bbox)
    weight = "bold" if bold else "normal"
    if subtext:
        ax.text(x, y + h * 0.15, text, ha="center", va="center",
                fontsize=fontsize, fontweight=weight, color=text_color, zorder=4)
        ax.text(x, y - h * 0.22, subtext, ha="center", va="center",
                fontsize=sub_fontsize, color="#555555", style="italic", zorder=4)
    else:
        ax.text(x, y, text, ha="center", va="center",
                fontsize=fontsize, fontweight=weight, color=text_color, zorder=4)


def draw_arrow(ax, x1, y1, x2, y2, label="", color=C_ARROW, fontsize=8):
    """Draw an annotated arrow between two points."""
    ax.annotate(
        "", xy=(x2, y2), xytext=(x1, y1),
        arrowprops=dict(
            arrowstyle="-|>", color=color,
            lw=1.6, mutation_scale=14
        ), zorder=2
    )
    if label:
        mx, my = (x1 + x2) / 2, (y1 + y2) / 2
        ax.text(mx + 0.05, my, label, ha="left", va="center",
                fontsize=fontsize, color=color, style="italic")


# ══════════════════════════════════════════════════════════════════════════════
# FIGURE 1 — FULL PIPELINE DIAGRAM
# ══════════════════════════════════════════════════════════════════════════════
def make_pipeline_diagram():
    fig, ax = plt.subplots(figsize=(14, 22))
    ax.set_xlim(0, 14)
    ax.set_ylim(0, 22)
    ax.axis("off")
    fig.patch.set_facecolor("white")

    cx = 7.0   # center x

    # ── ROW 1: Raw data ───────────────────────────────────────────────────────
    draw_box(ax, cx, 20.8, 6, 0.85,
             "Raw Network Traffic (PCAP / CSV)",
             C_DATA, fontsize=11, bold=True)
    draw_arrow(ax, cx, 20.38, cx, 19.72)

    # ── ROW 2: Dataset ────────────────────────────────────────────────────────
    draw_box(ax, cx, 19.35, 7.5, 0.95,
             "CICIDS-2017 Dataset",
             C_DATA, fontsize=11, bold=True,
             subtext="80 raw features · 2.8M flows · 14 attack types")
    draw_arrow(ax, cx, 18.88, cx, 18.15, label="load + split by label")

    # ── ROW 3: SPLIT ─────────────────────────────────────────────────────────
    # Diverting arrows
    ax.annotate("", xy=(3.5, 17.55), xytext=(cx, 18.15),
                arrowprops=dict(arrowstyle="-|>", color=C_TRAIN, lw=1.6,
                                connectionstyle="arc3,rad=0.3", mutation_scale=14), zorder=2)
    ax.annotate("", xy=(10.5, 17.55), xytext=(cx, 18.15),
                arrowprops=dict(arrowstyle="-|>", color=C_TEST, lw=1.6,
                                connectionstyle="arc3,rad=-0.3", mutation_scale=14), zorder=2)

    draw_box(ax, 3.5, 17.15, 5, 0.75,
             "Benign Traffic Only  (train set)",
             C_TRAIN, fontsize=9.5, bold=True)
    draw_box(ax, 10.5, 17.15, 5, 0.75,
             "Benign + Attack Traffic  (test set)",
             C_TEST, fontsize=9.5, bold=True)

    # ── ROW 4: PREPROCESSING (SHARED) ────────────────────────────────────────
    # Arrows from both split boxes converge
    ax.annotate("", xy=(cx, 15.38), xytext=(3.5, 16.77),
                arrowprops=dict(arrowstyle="-|>", color=C_PIPE, lw=1.6,
                                connectionstyle="arc3,rad=-0.25", mutation_scale=14), zorder=2)
    ax.annotate("", xy=(cx, 15.38), xytext=(10.5, 16.77),
                arrowprops=dict(arrowstyle="-|>", color=C_PIPE, lw=1.6,
                                connectionstyle="arc3,rad=0.25", mutation_scale=14), zorder=2)

    pipe_subtext = (
        "① Inf / NaN removal   "
        "② Outlier capping (IQR)   "
        "③ Log transform: x′ = log(1 + x)\n"
        "④ RobustScaler (fit on train only)   "
        "⑤ Feature engineering (ratio + timing)   "
        "⑥ Correlation-based feature removal"
    )
    draw_box(ax, cx, 14.55, 11, 1.65,
             "Preprocessing Pipeline",
             C_PIPE, fontsize=10, bold=True,
             subtext=pipe_subtext, sub_fontsize=8)

    # NO DATA LEAKAGE dashed red boundary
    leak_box = FancyBboxPatch(
        (1.1, 13.52), 11.8, 2.35,
        boxstyle="round,pad=0.05",
        facecolor="none", edgecolor=C_LEAK,
        linewidth=2.0, linestyle="dashed", zorder=5, alpha=0.85
    )
    ax.add_patch(leak_box)
    ax.text(1.35, 15.78, "NO DATA LEAKAGE BOUNDARY",
            ha="left", va="bottom", fontsize=8, color=C_LEAK,
            fontweight="bold", zorder=6)
    ax.text(cx, 13.58,
            "Fit parameters (median, IQR, log shift, correlation mask) estimated on BENIGN TRAIN only → applied to all",
            ha="center", va="bottom", fontsize=7.5, color=C_LEAK,
            style="italic", zorder=6)

    draw_arrow(ax, cx, 13.62, cx, 12.92)

    # ── ROW 5: MODEL TRAINING ────────────────────────────────────────────────
    model_sub = (
        "Trained on BENIGN ONLY\n"
        "K=12 components · covariance=full · threshold: 11th pct\n"
        "Anomaly score = −log p(x)"
    )
    draw_box(ax, cx, 12.35, 8, 1.05,
             "Model A: Gaussian Mixture Model (GMM)",
             C_MODEL, fontsize=10.5, bold=True,
             subtext=model_sub, sub_fontsize=8)
    draw_arrow(ax, cx, 11.82, cx, 11.12, label="anomaly scores")

    # ── ROW 6: THRESHOLD / EVALUATION ───────────────────────────────────────
    draw_box(ax, cx, 10.65, 7, 0.85,
             "Anomaly Detection Evaluation",
             C_EVAL, fontsize=10, bold=True,
             subtext="Threshold τ = 30.73  (log-likelihood at 11th percentile of train scores)",
             sub_fontsize=7.8)
    draw_arrow(ax, cx, 10.22, cx, 9.52)

    # ── ROW 7: RESULTS (3 side-by-side) ────────────────────────────────────
    draw_box(ax, 2.8, 9.08, 3.8, 0.85,
             "Confusion Matrix",
             C_EVAL, fontsize=9, bold=False,
             subtext="TP=316,219 · FP=42,487\nFN=20,286 · TN=337,100",
             sub_fontsize=7.5)
    draw_box(ax, cx, 9.08, 3.8, 0.85,
             "ROC Curve",
             C_EVAL, fontsize=9, bold=False,
             subtext="AUC-ROC = 0.9576",
             sub_fontsize=8.5)
    draw_box(ax, 11.2, 9.08, 3.8, 0.85,
             "Performance Metrics",
             C_EVAL, fontsize=9, bold=False,
             subtext="Precision=88.2% · Recall=93.97% · F1=90.97%",
             sub_fontsize=7.5)
    # Bracket arrows from eval to 3 boxes
    for bx in [2.8, cx, 11.2]:
        ax.annotate("", xy=(bx, 9.5), xytext=(cx, 10.22),
                    arrowprops=dict(arrowstyle="-|>", color=C_ARROW,
                                    lw=1.2, mutation_scale=12), zorder=2)

    draw_arrow(ax, cx, 8.65, cx, 7.95)

    # Per-attack-type box
    draw_box(ax, cx, 7.58, 11, 0.65,
             "Per-Attack-Type Detection Rates",
             C_EVAL, fontsize=9, bold=False,
             subtext="DDoS 99.9% · DoS Hulk 93.9% · FTP-Patator 98.9% · SSH-Patator 92.4%  "
                     "· Web-XSS 3.1% · Brute-Force 9.9%",
             sub_fontsize=7.5)

    draw_arrow(ax, cx, 7.25, cx, 6.55)

    # ── ROW 8: FUTURE PHASES ────────────────────────────────────────────────
    draw_box(ax, 3.8, 6.1, 5.5, 0.75,
             "Phase 2: Deep Learning\n(LSTM-AE / Transformer-AE)",
             C_FUTURE, fontsize=9, linestyle="dashed",
             subtext="Model B — In progress",
             sub_fontsize=7.8)
    draw_box(ax, 10.2, 6.1, 5.5, 0.75,
             "Phase 3: Hybrid System\n(Model A + Model B fusion)",
             C_FUTURE, fontsize=9, linestyle="dashed",
             subtext="Model C — Planned",
             sub_fontsize=7.8)
    ax.annotate("", xy=(3.8, 6.47), xytext=(cx, 7.25),
                arrowprops=dict(arrowstyle="-|>", color="#AAB7B8",
                                lw=1.2, mutation_scale=12, linestyle="dashed"), zorder=2)
    ax.annotate("", xy=(10.2, 6.47), xytext=(cx, 7.25),
                arrowprops=dict(arrowstyle="-|>", color="#AAB7B8",
                                lw=1.2, mutation_scale=12, linestyle="dashed"), zorder=2)
    ax.annotate("", xy=(7.95, 6.1), xytext=(6.55, 6.1),
                arrowprops=dict(arrowstyle="-|>", color="#AAB7B8",
                                lw=1.2, mutation_scale=12), zorder=2)
    ax.text(7.25, 6.15, "improves →", ha="center", va="bottom",
            fontsize=7, color="#888", style="italic")

    # ── LEGEND ───────────────────────────────────────────────────────────────
    legend_items = [
        mpatches.Patch(facecolor=C_DATA,   edgecolor=C_BORDER, label="Raw data / Dataset"),
        mpatches.Patch(facecolor=C_TRAIN,  edgecolor=C_BORDER, label="Train path (benign only)"),
        mpatches.Patch(facecolor=C_TEST,   edgecolor=C_BORDER, label="Test path (benign + attack)"),
        mpatches.Patch(facecolor=C_PIPE,   edgecolor=C_BORDER, label="Preprocessing pipeline"),
        mpatches.Patch(facecolor=C_MODEL,  edgecolor=C_BORDER, label="ML model"),
        mpatches.Patch(facecolor=C_EVAL,   edgecolor=C_BORDER, label="Evaluation / Results"),
        mpatches.Patch(facecolor=C_FUTURE, edgecolor=C_BORDER, label="Future phases (TBD)",
                       linestyle="dashed"),
        mpatches.Patch(facecolor="none",   edgecolor=C_LEAK,   label="No data leakage boundary",
                       linestyle="dashed"),
    ]
    ax.legend(handles=legend_items, loc="lower left",
              bbox_to_anchor=(0.01, 0.01),
              fontsize=8, framealpha=0.9, edgecolor="#AAAAAA",
              title="Color Legend", title_fontsize=8.5)

    # ── TITLE ─────────────────────────────────────────────────────────────────
    ax.text(cx, 21.65,
            "Phase 1 System Architecture — Adaptive Cyber-Physical Security",
            ha="center", va="center", fontsize=13, fontweight="bold",
            color=C_BORDER)
    ax.text(cx, 21.3,
            "Unsupervised Anomaly Detection Pipeline  |  CICIDS-2017  |  Model A: GMM",
            ha="center", va="center", fontsize=9, color="#555555", style="italic")

    plt.tight_layout()

    png_path = os.path.join(OUT_DIR, "architecture_diagram_phase1.png")
    pdf_path = os.path.join(OUT_DIR, "architecture_diagram_phase1.pdf")
    fig.savefig(png_path, dpi=150, bbox_inches="tight", facecolor="white")
    fig.savefig(pdf_path, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"Saved → {png_path}")
    print(f"Saved → {pdf_path}")


# ══════════════════════════════════════════════════════════════════════════════
# FIGURE 2 — ABLATION OVERVIEW
# ══════════════════════════════════════════════════════════════════════════════
def make_ablation_diagram():
    fig, ax = plt.subplots(figsize=(13, 4.5))
    ax.set_xlim(0, 13)
    ax.set_ylim(0, 4.5)
    ax.axis("off")
    fig.patch.set_facecolor("white")

    models = [
        {
            "x": 2.5, "label": "Model A\nGMM (Phase 1)",
            "color": C_MODEL, "status": "[Complete]",
            "metrics": "Precision 88.2% · Recall 93.97%\nF1 = 90.97%  ·  AUC = 95.76%",
        },
        {
            "x": 6.5, "label": "Model B\nLSTM-AE / Transformer-AE\n(Phase 2)",
            "color": C_TEST, "status": "[In progress]",
            "metrics": "F1 = TBD\nAUC = TBD",
        },
        {
            "x": 10.5, "label": "Model C\nHybrid System\n(Phase 3)",
            "color": C_FUTURE, "status": "[Planned]",
            "metrics": "F1 = TBD\nAUC = TBD",
        },
    ]

    for m in models:
        draw_box(ax, m["x"], 2.65, 3.2, 1.55,
                 m["label"], m["color"], fontsize=10, bold=True,
                 subtext=m["metrics"], sub_fontsize=8.5)
        ax.text(m["x"], 1.72, m["status"],
                ha="center", va="top", fontsize=8.5,
                color="#555", style="italic")

    # Arrows between models
    for x1, x2 in [(4.1, 4.9), (8.1, 8.9)]:
        ax.annotate("", xy=(x2, 2.65), xytext=(x1, 2.65),
                    arrowprops=dict(arrowstyle="-|>", color=C_ARROW,
                                    lw=2, mutation_scale=16), zorder=2)
        mx = (x1 + x2) / 2
        ax.text(mx, 2.82, "improves upon →",
                ha="center", va="bottom", fontsize=8, color=C_ARROW, style="italic")

    ax.text(6.5, 4.25,
            "Ablation Study Roadmap — Adaptive Cyber-Physical Security",
            ha="center", va="center", fontsize=12, fontweight="bold", color=C_BORDER)
    ax.text(6.5, 3.92,
            "Each phase builds on the previous · Weight: Phase 1 = 30%  |  Phase 2 = 30%  |  Phase 3 = 40%",
            ha="center", va="center", fontsize=8.5, color="#666", style="italic")

    # Weight annotation below each box
    weights = ["30% weight", "30% weight", "40% weight"]
    for m, w in zip(models, weights):
        ax.text(m["x"], 1.42, w, ha="center", va="top",
                fontsize=8, color="#888")

    plt.tight_layout()
    path = os.path.join(OUT_DIR, "ablation_overview.png")
    fig.savefig(path, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"Saved → {path}")


if __name__ == "__main__":
    print("Generating architecture diagrams …")
    make_pipeline_diagram()
    make_ablation_diagram()
    print("Done.")
