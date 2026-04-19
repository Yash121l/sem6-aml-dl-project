# Adaptive Cyber-Physical Security — Anomaly-Based Intrusion Detection

[![Phase 1](https://img.shields.io/badge/Phase%201-Complete-brightgreen)]()
[![Phase 2](https://img.shields.io/badge/Phase%202-Complete-brightgreen)]()
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)]()

## Project Overview

Modern industrial and cyber-physical systems face an ever-growing threat landscape in which
adversaries increasingly exploit zero-day vulnerabilities — attack vectors unseen by
signature-based intrusion detection systems (IDS). Traditional rule-based and supervised
approaches require labeled attack examples to train on; in practice, novel malware and
advanced persistent threats arrive faster than labels can be curated. This project addresses
that gap by building a **three-phase anomaly-based IDS** that learns only from normal benign
traffic and flags any deviation as a potential intrusion.

Our methodology follows a rigorous academic ablation roadmap. Phase 1 establishes a classical
machine learning baseline (Model A — GMM) evaluated on the widely-used CICIDS-2017 benchmark.
Phase 2 introduces a deep sequential representation learner (Model B — LSTM-AE / Transformer-AE),
and Phase 3 will combine both into a hybrid ensemble (Model C).

## Team

| Name | Role |
|------|------|
| Yash L. | EDA, preprocessing pipeline, DL architecture, report |
| Rishabh | Model training, evaluation, ablation study |

## Repository Structure

```
sem6-aml-dl-project/
├── README.md
├── requirements.txt
├── .gitignore
│
├── data/
│   └── README.md                        # Download instructions for CICIDS-2017
│
├── notebooks/
│   ├── stage1_eda.ipynb                 # EDA: 10 plots, class distribution
│   ├── stage2_preprocessing.ipynb       # Feature engineering, scaling, correlation removal
│   ├── stage3_models.ipynb              # Model A: IF / OCSVM / GMM training & selection
│   ├── stage4_phase2_architecture.ipynb # Phase 2 theory: LSTM gates, attention, sequence design
│   ├── stage5_lstm_ae.ipynb             # LSTM-AE training, evaluation, per-attack analysis
│   └── stage6_transformer_ae.ipynb      # Transformer-AE, head-to-head, ablation study
│
├── scripts/
│   └── run_ablation.py                  # Laptop-safe ablation script (chunked inference)
│
├── src/
│   ├── __init__.py
│   ├── features.py                      # FeatureEngineer class (5-stage pipeline)
│   ├── models.py                        # AnomalyDetector base + IF / OCSVM / GMM / LSTMAEDetector
│   └── evaluate.py                      # Evaluation utilities and plot generators
│
├── models/
│   ├── model_a_gmm.pkl                  # Phase 1 GMM (K=12, full covariance)
│   ├── model_a_threshold.npy            # GMM decision threshold τ
│   ├── lstm_ae_best.keras               # LSTM-AE best checkpoint (262,978 params)
│   ├── lstm_ae_threshold.npy            # LSTM-AE anomaly threshold
│   ├── transformer_ae_best.keras        # Transformer-AE best checkpoint
│   ├── model_b_final.keras              # Selected Model B (winner of head-to-head)
│   └── model_b_threshold.npy            # Model B decision threshold
│
├── outputs/
│   ├── eda/                             # 10 EDA plots
│   ├── preprocessing/                   # X_train.npy, X_test.npy, y_test.npy, scalers
│   ├── sequences/                       # X_train_seq.npy (121464,50,34), X_test_seq.npy
│   └── models/                          # All model analysis plots
│
├── results/
│   ├── model_a_metrics.csv              # Phase 1: Baseline, IF, OCSVM, GMM metrics
│   ├── lstm_ae_metrics.csv              # LSTM-AE detailed metrics
│   ├── transformer_ae_metrics.csv       # Transformer-AE metrics
│   ├── model_b_comparison.csv           # LSTM-AE vs Transformer-AE head-to-head
│   ├── model_b_metrics.csv              # Final Model B (winner) metrics
│   ├── model_b_per_attack_comparison.csv
│   ├── phase2_ablation_internal.csv     # 4-variant internal ablation table
│   └── ablation_table_all_phases.csv    # Cross-phase ablation (Baseline→GMM→DL→Hybrid)
│
└── report/
    ├── phase1_report.pdf                # Phase 1 IEEE-format report
    └── phase2_report.tex                # Phase 2 LaTeX source (compile with pdflatex)
```

## Phase 1 Results — Model A (Gaussian Mixture Model)

| Model | Precision | Recall | F1-Score | AUC-ROC |
|-------|-----------|--------|----------|---------|
| Statistical Baseline | 52.1% | 48.3% | 50.1% | 61.2% |
| Isolation Forest | 75.4% | 51.8% | 61.4% | 80.3% |
| One-Class SVM | 76.8% | 74.9% | 75.9% | 87.2% |
| **GMM (Model A)** | **88.3%** | **93.8%** | **90.97%** | **95.76%** |

Model A hyperparameters: `n_components=12`, `covariance_type='full'`, `threshold_percentile=11`

### Per-Attack Detection Rates (Model A — GMM)

| Attack Type | Total Flows | Detection Rate |
|-------------|-------------|----------------|
| DDoS | 128,016 | 99.9% |
| FTP-Patator | 5,933 | 98.9% |
| DoS Slowhttptest | 5,228 | 99.5% |
| DoS slowloris | 5,385 | 69.3% |
| SSH-Patator | 3,219 | 92.4% |
| DoS Hulk | 172,849 | 93.9% |
| DoS GoldenEye | 10,286 | 54.8% |
| PortScan | 1,958 | 72.6% |
| **Bot** | **1,441** | **45.2%** ← Phase 2 target |
| **Infiltration** | **36** | **33.1%** ← Phase 2 target |
| Web Attack - Brute Force | 1,470 | 9.9% |
| Web Attack - XSS | 652 | 3.1% |

## Phase 2 Results — Model B (LSTM Autoencoder)

| Metric | Value | Note |
|--------|-------|------|
| Precision | 47.0% | Permissive threshold |
| Recall | 100.0% | All attacks detected |
| **F1-Score** | **63.94%** | |
| **AUC-ROC** | **52.19%** | See note below |
| Window size | 50 flows | ~5 min at enterprise rate |
| Latent dimension | 32 | 53× compression of 1,700-dim input |
| Parameters | 262,978 | |
| Inference | 0.83 ms/sequence | CPU |

> **AUC note:** The 52.19% AUC reflects evaluation on the Phase 1 shuffled test set. Because
> `train_test_split(shuffle=True)` was used in Phase 1, temporal ordering is destroyed and every
> 50-flow test window contains a mix of benign and attack flows (~47% attack prevalence). Window-level
> discrimination is therefore near-impossible by design. A temporally ordered evaluation in Phase 3
> is expected to reveal the model's genuine discriminative capability.

## Cross-Phase Ablation Roadmap

| Model | Phase | Method | F1 | AUC | Status |
|-------|-------|--------|----|-----|--------|
| Statistical Baseline | 1 | z-score | 50.1% | 61.2% | Complete |
| Isolation Forest | 1 | Ensemble | 61.4% | 80.3% | Complete |
| One-Class SVM | 1 | Kernel | 75.9% | 87.2% | Complete |
| **GMM (Model A)** | **1** | **Gaussian Mixture** | **90.97%** | **95.76%** | **Complete** |
| **LSTM-AE (Model B)** | **2** | **Deep Learning AE** | **63.94%** | **52.19%** | **Complete** |
| Hybrid (Model C) | 3 | GMM + DL ensemble | TBD | TBD | Planned |

## Quick Start

```bash
git clone https://github.com/Yash121l/sem6-aml-dl-project.git
cd sem6-aml-dl-project

# Install dependencies (includes tensorflow==2.14.0)
pip install -r requirements.txt

# Download CICIDS-2017 from https://www.unb.ca/cic/datasets/ids-2017.html
# Place CSV files in data/CICIDS2017/ (see data/README.md)

# Run notebooks in order:
jupyter notebook notebooks/stage1_eda.ipynb
```

## Notebooks (run in order)

| Notebook | Description | Key Outputs |
|----------|-------------|-------------|
| `stage1_eda.ipynb` | 10 EDA plots, class distribution, t-SNE | `outputs/eda/` |
| `stage2_preprocessing.ipynb` | Log transform, RobustScaler, feature engineering, correlation removal | `outputs/preprocessing/` |
| `stage3_models.ipynb` | IF, OCSVM, GMM training; grid search; Model A selection | `outputs/models/`, `models/` |
| `stage4_phase2_architecture.ipynb` | LSTM/Transformer theory, sequence construction, architecture diagrams | `outputs/sequences/` |
| `stage5_lstm_ae.ipynb` | LSTM-AE training, evaluation, per-attack analysis, latent space | `outputs/models/` |
| `stage6_transformer_ae.ipynb` | Transformer-AE, head-to-head comparison, ablation study | `results/` |

## Key Design Decisions

- **Train on benign only** — enables zero-day detection without any attack labels.
- **GMM selected as Model A** — F1=90.97% vs 75.9% (OCSVM). Full-covariance GMM models correlated feature clusters corresponding to different traffic regimes.
- **LSTM-AE for Phase 2** — Phase 1 GMM failed on temporal attacks (Bot 45%, Infiltration 33%). Sequence models detect patterns invisible at the individual flow level.
- **Window W=50** — covers ~5 minutes of traffic, capturing C2 beacon intervals and multi-stage attack sequences.
- **RobustScaler over StandardScaler** — network flow features contain extreme outliers from flood attacks. Fitted only on benign training data.

## Evaluation Methodology

```
Train  : Benign flows only (1,518,344 flows) — model learns the normal distribution
Test   : Benign + attack flows (716,092 flows) — labels used for evaluation only
Phase 2: 121,464 training windows (W=50, stride=10), 716,043 test windows (stride=1)
```

## Phase Roadmap

| Phase | Description | Status | Weight |
|-------|-------------|--------|--------|
| Phase 1 | ML baseline — Model A (GMM) | **Complete** | 30% |
| Phase 2 | Deep Learning — Model B (LSTM-AE + Transformer-AE) | **Complete** | 30% |
| Phase 3 | Hybrid ensemble — Model C (GMM + DL score fusion) | Planned | 40% |

## References

1. Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). Toward Generating a New Intrusion Detection Dataset. *ICISSP 2018*.
2. Liu, F. T., Ting, K. M., & Zhou, Z.-H. (2008). Isolation Forest. *ICDM 2008*.
3. Schölkopf, B. et al. (2001). Estimating the support of a high-dimensional distribution. *Neural Computation*.
4. Bishop, C. M. (2006). *Pattern Recognition and Machine Learning*. Springer.
5. Hochreiter, S., & Schmidhuber, J. (1997). Long short-term memory. *Neural Computation, 9*(8).
6. Vaswani, A. et al. (2017). Attention is all you need. *NeurIPS 2017*.
7. Mirsky, Y. et al. (2018). Kitsune: An ensemble of autoencoders for online network intrusion detection. *NDSS 2018*.
8. Zong, B. et al. (2018). Deep autoencoding Gaussian mixture model for unsupervised anomaly detection. *ICLR 2018*.
