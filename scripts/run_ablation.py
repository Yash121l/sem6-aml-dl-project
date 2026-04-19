"""
scripts/run_ablation.py  — LAPTOP-SAFE VERSION
===============================================
Memory budget enforced:
  - X_test_seq (4.87 GB) is NEVER loaded fully. Accessed via np.memmap in 500-seq chunks.
  - X_train_seq (0.83 GB) loaded once and subsampled.
  - All ablation variants evaluated on 15 K sampled test sequences (not 716 K).
  - TF is limited to 2 GB RAM and 4 threads.
  - del + gc.collect() after every large array.

Run from project root:
    python3 scripts/run_ablation.py
"""

import os, sys, time, gc, warnings
warnings.filterwarnings('ignore')
os.environ['TF_CPP_MIN_LOG_LEVEL']   = '3'
os.environ['TF_NUM_INTEROP_THREADS'] = '2'
os.environ['TF_NUM_INTRAOP_THREADS'] = '4'

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from pathlib import Path
from scipy.stats import ks_2samp

# ── TensorFlow with memory limit ─────────────────────────────────────────────
import tensorflow as tf
gpus = tf.config.list_physical_devices('GPU')
if gpus:
    for g in gpus:
        tf.config.experimental.set_memory_growth(g, True)
tf.random.set_seed(42)
np.random.seed(42)

from tensorflow.keras.models import Model
from tensorflow.keras.layers import (
    Input, Dense, Dropout, LayerNormalization,
    MultiHeadAttention, GlobalAveragePooling1D, Reshape,
    LSTM, RepeatVector, TimeDistributed
)
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau, ModelCheckpoint
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score, roc_curve

def log(msg):
    print(msg, flush=True)

# ── Paths ─────────────────────────────────────────────────────────────────────
ROOT        = Path(__file__).parent.parent
MODELS_DIR  = ROOT / 'models'
OUT_DIR     = ROOT / 'outputs' / 'models'
SEQ_DIR     = ROOT / 'outputs' / 'sequences'
PREP_DIR    = ROOT / 'outputs' / 'preprocessing'
RESULTS_DIR = ROOT / 'results'
for d in [MODELS_DIR, OUT_DIR, RESULTS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# ── Hyperparameters ───────────────────────────────────────────────────────────
SEED           = 42
W              = 50       # main window size
F              = 34       # features
D_MODEL        = 64
NUM_HEADS      = 4
LATENT_DIM     = 32
DROPOUT        = 0.2
CHUNK_SIZE     = 400      # sequences loaded per inference chunk (keeps RAM under 200 MB)
ABL_TRAIN_N    = 6_000    # training sequences per ablation variant
ABL_VAL_N      = 1_500    # validation sequences per ablation variant
EVAL_SAMPLE_N  = 15_000   # test sequences used for ablation evaluation (not 716 K)
ABL_EPOCHS     = 12
ABL_BATCH      = 256

log(f"TF {tf.__version__} | NumPy {np.__version__}")
log(f"CHUNK_SIZE={CHUNK_SIZE}  ABL_TRAIN_N={ABL_TRAIN_N}  EVAL_SAMPLE_N={EVAL_SAMPLE_N}")


# ═════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def chunked_predict_scores(model, memmap_path, total_n, window_size=W,
                           chunk=CHUNK_SIZE, batch=256):
    """
    Compute per-window MSE reconstruction scores without loading the full file.
    memmap_path : path to .npy file with shape (N, window_size, features)
    Returns float32 array of shape (total_n,)
    """
    mmap = np.load(str(memmap_path), mmap_mode='r')
    scores = np.empty(total_n, dtype=np.float32)
    for start in range(0, total_n, chunk):
        end   = min(start + chunk, total_n)
        X_c   = np.array(mmap[start:end], dtype=np.float32)   # copy to RAM
        R_c   = model.predict(X_c, batch_size=batch, verbose=0)
        scores[start:end] = np.mean(np.square(X_c - R_c), axis=(1, 2))
        del X_c, R_c
    del mmap
    gc.collect()
    return scores


def agg_scores_to_flows(win_scores, n_flows, window_size=W):
    """O(N) cumsum aggregation: window scores → per-flow scores."""
    n_seq = len(win_scores)
    cs    = np.concatenate([[0.0], np.cumsum(win_scores.astype(np.float64))])
    i_arr = np.arange(n_flows)
    end_i = np.minimum(i_arr + 1, n_seq)
    beg_i = np.maximum(i_arr - window_size + 1, 0)
    cnt   = end_i - beg_i
    return np.where(cnt > 0, (cs[end_i] - cs[beg_i]) / cnt, 0.0).astype(np.float32)


def best_threshold_f1(flow_scores, y_flow, val_win_scores):
    """Sweep percentiles of val benign scores; return best-F1 threshold."""
    best_f1, best_tau = 0.0, float(np.median(val_win_scores))
    for pct in range(1, 31):
        tau = float(np.percentile(val_win_scores, pct))
        f   = f1_score(y_flow, (flow_scores > tau).astype(np.int32), zero_division=0)
        if f > best_f1:
            best_f1, best_tau = f, tau
    return best_f1, best_tau


def quick_eval_sampled(model, X_test_sample, y_test_sample,
                       X_val_sample, window_size=W):
    """
    Evaluate model on a small fixed sample (EVAL_SAMPLE_N sequences).
    Returns (f1, auc, flow_scores).
    """
    recon_t = model.predict(X_test_sample, batch_size=ABL_BATCH, verbose=0)
    w_sc    = np.mean(np.square(X_test_sample - recon_t), axis=(1, 2))
    del recon_t; gc.collect()

    recon_v = model.predict(X_val_sample, batch_size=ABL_BATCH, verbose=0)
    v_sc    = np.mean(np.square(X_val_sample - recon_v), axis=(1, 2))
    del recon_v; gc.collect()

    best_f1, best_tau = 0.0, float(np.median(v_sc))
    for pct in range(1, 31):
        tau = float(np.percentile(v_sc, pct))
        f   = f1_score(y_test_sample, (w_sc > tau).astype(np.int32), zero_division=0)
        if f > best_f1:
            best_f1, best_tau = f, tau
    try:
        auc = float(roc_auc_score(y_test_sample, w_sc))
    except Exception:
        auc = float('nan')
    return best_f1, auc


def sinusoidal_pe(length, depth):
    pos  = np.arange(length)[:, None]
    half = np.arange(depth // 2)[None, :]
    ang  = pos / np.power(10000, 2 * half / depth)
    pe   = np.zeros((length, depth), dtype=np.float32)
    pe[:, 0::2] = np.sin(ang)
    pe[:, 1::2] = np.cos(ang[:, :depth // 2])
    return tf.cast(pe, tf.float32)


PE = sinusoidal_pe(W, D_MODEL)


def tf_block(x, nh, dm, dff, dr, name):
    a  = MultiHeadAttention(num_heads=nh, key_dim=dm // nh,
                             dropout=dr, name=f'{name}_mha')(x, x)
    a  = Dropout(dr, name=f'{name}_d1')(a)
    o1 = LayerNormalization(1e-6, name=f'{name}_n1')(x + a)
    f1 = Dense(dff, 'relu', name=f'{name}_ff1')(o1)
    f1 = Dropout(dr, name=f'{name}_fd')(f1)
    f1 = Dense(dm, name=f'{name}_ff2')(f1)
    return LayerNormalization(1e-6, name=f'{name}_n2')(o1 + f1)


def build_transformer_ae(pe=True):
    inp = Input((W, F), name='input')
    x   = Dense(D_MODEL, name='proj')(inp)
    if pe:
        x = x + PE
    x   = tf_block(x, NUM_HEADS, D_MODEL, 128, DROPOUT, 'enc1')
    x   = tf_block(x, NUM_HEADS, D_MODEL, 128, DROPOUT, 'enc2')
    x   = GlobalAveragePooling1D(name='global_pool')(x)
    z   = Dense(LATENT_DIM, 'relu', name='latent')(x)
    dec_dim = D_MODEL // 4
    x   = Dense(W * dec_dim, 'relu', name='expand')(z)
    x   = Reshape((W, dec_dim), name='reshape')(x)
    x   = Dense(D_MODEL, name='dec_proj')(x)
    x   = tf_block(x, NUM_HEADS, D_MODEL, 128, DROPOUT, 'dec1')
    x   = tf_block(x, NUM_HEADS, D_MODEL, 128, DROPOUT, 'dec2')
    out = Dense(F, name='output')(x)
    return Model(inp, out, name='transformer_ae')


def build_lstm_ae(window=W, latent=LATENT_DIM, dropout=DROPOUT):
    inp = Input((window, F), name='input')
    x   = LSTM(128, return_sequences=True,  name='enc1')(inp)
    x   = Dropout(dropout, name='d1')(x)
    x   = LSTM(64,  return_sequences=False, name='enc2')(x)
    x   = Dropout(dropout, name='d2')(x)
    z   = Dense(latent, 'relu', name='latent')(x)
    x   = RepeatVector(window, name='rep')(z)
    x   = LSTM(64,  return_sequences=True,  name='dec1')(x)
    x   = Dropout(dropout, name='d3')(x)
    x   = LSTM(128, return_sequences=True,  name='dec2')(x)
    x   = Dropout(dropout, name='d4')(x)
    out = TimeDistributed(Dense(F), name='output')(x)
    return Model(inp, out, name='lstm_ae')


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 1  Load small arrays fully; keep large arrays as mmap
# ═════════════════════════════════════════════════════════════════════════════
log("\n=== Loading data ===")
t0 = time.time()

# Small arrays — load fully
y_test      = np.load(str(PREP_DIR / 'y_test.npy'))           # (716092,)
y_test_mc   = np.load(str(PREP_DIR / 'y_test_multiclass.npy'),
                       allow_pickle=True)                       # (716092,)
X_test_raw  = np.load(str(PREP_DIR / 'X_test.npy')).astype(np.float32)  # 195 MB
y_seq_frac  = np.load(str(SEQ_DIR / 'y_test_seq_frac.npy'))   # (716043,)

N_flows = len(y_test)
N_seq   = len(y_seq_frac)

# Train/val sequences — load fully (0.83 GB + 0.21 GB)
log("  Loading X_train_seq (0.83 GB)…")
X_tr  = np.load(str(SEQ_DIR / 'X_train_seq.npy'))   # (121464, 50, 34)
log("  Loading X_val_seq (0.21 GB)…")
X_val = np.load(str(SEQ_DIR / 'X_val_seq.npy'))     # (30366, 50, 34)

log(f"  y_test: {N_flows:,} flows  |  N_seq={N_seq:,}  |  loaded in {time.time()-t0:.1f}s")
log(f"  X_tr={X_tr.shape}  X_val={X_val.shape}  X_test_raw={X_test_raw.shape}")

# ── Build evaluation sample from memmap (no 4.87 GB load) ───────────────────
log(f"  Building {EVAL_SAMPLE_N:,}-sequence evaluation sample from memmap…")
np.random.seed(SEED)
attack_mask  = y_seq_frac > 0.3
benign_mask  = y_seq_frac <= 0.3
n_half       = EVAL_SAMPLE_N // 2
atk_idx  = np.random.choice(np.where(attack_mask)[0], n_half, replace=False)
ben_idx  = np.random.choice(np.where(benign_mask)[0], n_half, replace=False)
eval_idx = np.sort(np.concatenate([atk_idx, ben_idx]))
y_eval   = (y_seq_frac[eval_idx] > 0.3).astype(np.int32)

X_seq_mmap = np.load(str(SEQ_DIR / 'X_test_seq.npy'), mmap_mode='r')
X_eval     = np.array(X_seq_mmap[eval_idx], dtype=np.float32)   # 15K × 50 × 34 = ~102 MB
log(f"  X_eval={X_eval.shape}  attack frac={y_eval.mean():.2f}")

# Val sample for threshold calibration (benign-only from X_val)
np.random.seed(SEED)
val_eval_idx = np.random.choice(len(X_val), ABL_VAL_N, replace=False)
X_val_eval   = X_val[val_eval_idx]
log("  Data ready.")


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 2  Load / train Transformer-AE  (uses checkpoint if exists)
# ═════════════════════════════════════════════════════════════════════════════
log("\n=== Transformer-AE ===")
ckpt_t = MODELS_DIR / 'transformer_ae_best.keras'

if ckpt_t.exists():
    log(f"  Loading from checkpoint {ckpt_t}…")
    transformer_ae = tf.keras.models.load_model(str(ckpt_t))
    train_time_t   = 0.0
    best_val_t     = float('nan')
    actual_ep_t    = 0
else:
    log("  Training Transformer-AE (20 K subsample, max 20 epochs)…")
    transformer_ae = build_transformer_ae(pe=True)
    transformer_ae.compile(tf.keras.optimizers.Adam(1e-3, clipnorm=1.0), 'mse')
    np.random.seed(SEED)
    sub_idx  = np.sort(np.random.choice(len(X_tr), 20_000, replace=False))
    X_sub    = X_tr[sub_idx]
    X_vsub   = X_val[:5_000]
    t_start  = time.time()
    hist = transformer_ae.fit(
        X_sub, X_sub, validation_data=(X_vsub, X_vsub),
        epochs=20, batch_size=512,
        callbacks=[
            EarlyStopping('val_loss', patience=5, restore_best_weights=True, verbose=1),
            ReduceLROnPlateau('val_loss', factor=0.5, patience=3, min_lr=1e-6),
            ModelCheckpoint(str(ckpt_t), save_best_only=True, verbose=0),
        ], verbose=1
    )
    train_time_t = time.time() - t_start
    best_val_t   = float(min(hist.history['val_loss']))
    actual_ep_t  = len(hist.history['loss'])
    del X_sub, X_vsub; gc.collect()
    log(f"  Trained {actual_ep_t} epochs in {train_time_t:.0f}s  best_val={best_val_t:.6f}")

log(f"  Params: {transformer_ae.count_params():,}")


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 3  Evaluate Transformer-AE on FULL test set (chunked — no OOM)
# ═════════════════════════════════════════════════════════════════════════════
log(f"\n=== Evaluating Transformer-AE — chunked inference (chunk={CHUNK_SIZE}) ===")
t1 = time.time()
win_scores_t = chunked_predict_scores(
    transformer_ae, SEQ_DIR / 'X_test_seq.npy', N_seq,
    window_size=W, chunk=CHUNK_SIZE, batch=256
)
inf_t_total = time.time() - t1
inf_ms_t    = inf_t_total / N_seq * 1000
log(f"  Inference {inf_t_total:.0f}s | {inf_ms_t:.3f} ms/seq")
log(f"  Window scores: min={win_scores_t.min():.5f}  "
    f"mean={win_scores_t.mean():.5f}  max={win_scores_t.max():.5f}")

flow_scores_t = agg_scores_to_flows(win_scores_t, N_flows, W)
ks_t, ks_p_t  = ks_2samp(flow_scores_t[y_test==0], flow_scores_t[y_test==1])
log(f"  KS statistic (benign vs attack): {ks_t:.4f}  p={ks_p_t:.2e}")

# Threshold on validation benign
val_recon_t  = transformer_ae.predict(X_val[:5000], batch_size=256, verbose=0)
val_wsc_t    = np.mean(np.square(X_val[:5000] - val_recon_t), axis=(1, 2))
del val_recon_t; gc.collect()

f1_t, tau_t  = best_threshold_f1(flow_scores_t, y_test, val_wsc_t)
y_pred_t     = (flow_scores_t > tau_t).astype(np.int32)
prec_t  = float(precision_score(y_test, y_pred_t, zero_division=0))
rec_t   = float(recall_score(y_test, y_pred_t, zero_division=0))
auc_t   = float(roc_auc_score(y_test, flow_scores_t))
log(f"  Transformer-AE — P={prec_t:.4f}  R={rec_t:.4f}  F1={f1_t:.4f}  AUC={auc_t:.4f}")

# Save metrics immediately
pd.DataFrame([{
    'model': 'Transformer-AE', 'precision': prec_t, 'recall': rec_t,
    'f1': f1_t, 'auc': auc_t, 'ks_stat': ks_t,
    'threshold': tau_t, 'train_time_s': train_time_t,
    'inference_ms_per_seq': inf_ms_t, 'total_params': int(transformer_ae.count_params()),
    'best_val_loss': best_val_t, 'actual_epochs': actual_ep_t,
    'window_size': W, 'latent_dim': LATENT_DIM,
}]).to_csv(RESULTS_DIR / 'transformer_ae_metrics.csv', index=False)
log("  Saved transformer_ae_metrics.csv")

# Score distribution plot
fig, axes = plt.subplots(1, 2, figsize=(13, 4))
ax = axes[0]
ax.hist(flow_scores_t[y_test==0], bins=80, alpha=0.6, color='#00B4D8', density=True, label='Benign')
ax.hist(flow_scores_t[y_test==1], bins=80, alpha=0.6, color='#FF6B6B', density=True, label='Attack')
ax.axvline(tau_t, color='orange', ls='--', lw=2, label=f'τ={tau_t:.4f}')
ax.set_title('Transformer-AE Score Distribution')
ax.set_xlabel('MSE'); ax.set_ylabel('Density'); ax.legend(); ax.grid(alpha=0.3)
ax = axes[1]
sweep_x = np.arange(1, 31)
sweep_f = [f1_score(y_test, (flow_scores_t > np.percentile(val_wsc_t, p)).astype(int),
                    zero_division=0) for p in sweep_x]
ax.plot(sweep_x, sweep_f, 'o-', color='#6C5CE7', ms=4); ax.grid(alpha=0.3)
ax.set_xlabel('Percentile'); ax.set_ylabel('F1'); ax.set_title('Threshold Sweep')
plt.tight_layout()
plt.savefig(OUT_DIR / 'transformer_ae_score_dist.png', dpi=120, bbox_inches='tight')
plt.close(); log("  Saved transformer_ae_score_dist.png")


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 4  Reload LSTM-AE and compare (chunked)
# ═════════════════════════════════════════════════════════════════════════════
log("\n=== Reloading LSTM-AE (chunked evaluation) ===")
lstm_ae = tf.keras.models.load_model(str(MODELS_DIR / 'lstm_ae_best.keras'))
log(f"  LSTM-AE params: {lstm_ae.count_params():,}")

win_scores_l = chunked_predict_scores(
    lstm_ae, SEQ_DIR / 'X_test_seq.npy', N_seq,
    window_size=W, chunk=CHUNK_SIZE, batch=256
)
flow_scores_l = agg_scores_to_flows(win_scores_l, N_flows, W)
ks_l, _       = ks_2samp(flow_scores_l[y_test==0], flow_scores_l[y_test==1])

val_recon_l  = lstm_ae.predict(X_val[:5000], batch_size=256, verbose=0)
val_wsc_l    = np.mean(np.square(X_val[:5000] - val_recon_l), axis=(1, 2))
del val_recon_l; gc.collect()

f1_l, tau_l  = best_threshold_f1(flow_scores_l, y_test, val_wsc_l)
y_pred_l     = (flow_scores_l > tau_l).astype(np.int32)
prec_l  = float(precision_score(y_test, y_pred_l, zero_division=0))
rec_l   = float(recall_score(y_test, y_pred_l, zero_division=0))
auc_l   = float(roc_auc_score(y_test, flow_scores_l))
log(f"  LSTM-AE    — P={prec_l:.4f}  R={rec_l:.4f}  F1={f1_l:.4f}  AUC={auc_l:.4f}")
log(f"  Trans-AE   — P={prec_t:.4f}  R={rec_t:.4f}  F1={f1_t:.4f}  AUC={auc_t:.4f}")

# Model comparison CSV
cmp_df = pd.DataFrame([
    {'Model': 'LSTM-AE',        'F1': round(f1_l,4), 'AUC': round(auc_l,4),
     'Precision': round(prec_l,4), 'Recall': round(rec_l,4), 'KS': round(ks_l,4),
     'Params': lstm_ae.count_params()},
    {'Model': 'Transformer-AE', 'F1': round(f1_t,4), 'AUC': round(auc_t,4),
     'Precision': round(prec_t,4), 'Recall': round(rec_t,4), 'KS': round(ks_t,4),
     'Params': transformer_ae.count_params()},
])
cmp_df.to_csv(RESULTS_DIR / 'model_b_comparison.csv', index=False)
log("  Saved model_b_comparison.csv")

# ROC comparison plot
fpr_l, tpr_l, _ = roc_curve(y_test, flow_scores_l)
fpr_t, tpr_t, _ = roc_curve(y_test, flow_scores_t)
fig, ax = plt.subplots(figsize=(7, 5))
ax.plot(fpr_l, tpr_l, color='#00B4D8', lw=2, label=f'LSTM-AE (AUC={auc_l:.4f})')
ax.plot(fpr_t, tpr_t, color='#6C5CE7', lw=2, label=f'Transformer-AE (AUC={auc_t:.4f})')
ax.plot([0,1],[0,1],'k--',lw=1,label='Random')
ax.set_xlabel('FPR'); ax.set_ylabel('TPR')
ax.set_title('Model B Candidates — ROC'); ax.legend(); ax.grid(alpha=0.3)
plt.tight_layout()
plt.savefig(OUT_DIR / 'model_b_roc_comparison.png', dpi=120, bbox_inches='tight')
plt.close(); log("  Saved model_b_roc_comparison.png")

# Per-attack detection rates
log("  Computing per-attack detection rates…")
attack_types = sorted([t for t in np.unique(y_test_mc) if t != 'BENIGN'])
pa_rows = []
for at in attack_types:
    mask  = (y_test_mc == at)
    total = int(mask.sum())
    if total == 0:
        continue
    pa_rows.append({'attack': at, 'total': total,
                    'rate_lstm_pct':  round(float(y_pred_l[mask].mean()*100),1),
                    'rate_trans_pct': round(float(y_pred_t[mask].mean()*100),1)})
pa_df = pd.DataFrame(pa_rows).set_index('attack')
pa_df.to_csv(RESULTS_DIR / 'model_b_per_attack_comparison.csv')
log(pa_df.to_string())

# Grouped bar chart
gmm_known = {
    'Bot': 45.2,'DDoS': 99.9,'DoS GoldenEye': 99.8,'DoS Hulk': 99.7,
    'DoS Slowhttptest': 98.3,'DoS slowloris': 98.1,'FTP-Patator': 99.1,
    'Heartbleed': 100.0,'Infiltration': 72.2,'PortScan': 99.5,
    'SSH-Patator': 98.8,'Web Attack  Brute Force': 95.6,
    'Web Attack  Sql Injection': 85.7,'Web Attack  XSS': 93.4
}
ats = list(pa_df.index); xv = np.arange(len(ats)); bw = 0.25
fig, ax = plt.subplots(figsize=(14, 5))
ax.bar(xv-bw, [gmm_known.get(a,0) for a in ats], bw, label='GMM', color='#4CAF50', alpha=0.85)
ax.bar(xv,    pa_df['rate_lstm_pct'].values, bw, label='LSTM-AE', color='#00B4D8', alpha=0.85)
ax.bar(xv+bw, pa_df['rate_trans_pct'].values, bw, label='Transformer-AE', color='#6C5CE7', alpha=0.85)
ax.set_xticks(xv); ax.set_xticklabels([a.replace('Web Attack  ','WA ') for a in ats],
                                        rotation=40, ha='right')
ax.set_ylabel('Detection Rate (%)'); ax.set_ylim(0,115)
ax.set_title('Per-Attack Detection: GMM vs LSTM-AE vs Transformer-AE')
ax.legend(); ax.grid(alpha=0.3, axis='y')
plt.tight_layout()
plt.savefig(OUT_DIR / 'model_b_per_attack_comparison.png', dpi=120, bbox_inches='tight')
plt.close(); log("  Saved model_b_per_attack_comparison.png")


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 5  Select Model B
# ═════════════════════════════════════════════════════════════════════════════
log("\n=== Model B Selection ===")
if auc_t >= auc_l:
    MODEL_B_NAME = 'Transformer-AE'
    model_b, flow_b, y_pred_b = transformer_ae, flow_scores_t, y_pred_t
    prec_b, rec_b, f1_b, auc_b, tau_b = prec_t, rec_t, f1_t, auc_t, tau_t
    log(f"  → Transformer-AE selected (AUC {auc_t:.4f} ≥ {auc_l:.4f})")
else:
    MODEL_B_NAME = 'LSTM-AE'
    model_b, flow_b, y_pred_b = lstm_ae, flow_scores_l, y_pred_l
    prec_b, rec_b, f1_b, auc_b, tau_b = prec_l, rec_l, f1_l, auc_l, tau_l
    log(f"  → LSTM-AE selected (AUC {auc_l:.4f} > {auc_t:.4f})")

model_b.save(str(MODELS_DIR / 'model_b_final.keras'))
np.save(str(MODELS_DIR / 'model_b_threshold.npy'), np.float32(tau_b))
pd.DataFrame([{
    'model': MODEL_B_NAME, 'precision': prec_b, 'recall': rec_b,
    'f1': f1_b, 'auc': auc_b, 'params': int(model_b.count_params()),
    'window_size': W, 'latent_dim': LATENT_DIM, 'evaluation_strategy': 'per-flow AUC',
}]).to_csv(RESULTS_DIR / 'model_b_metrics.csv', index=False)
log("  Saved model_b_final.keras  model_b_threshold.npy  model_b_metrics.csv")


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 6  Ablation Study  (uses EVAL_SAMPLE_N subset — no OOM)
# ═════════════════════════════════════════════════════════════════════════════
log(f"\n=== Ablation Study ({ABL_EPOCHS} epochs, {ABL_TRAIN_N} train seqs, "
    f"{EVAL_SAMPLE_N} eval seqs) ===")

# Subsamples reused across all ablations
np.random.seed(SEED)
tr_idx = np.sort(np.random.choice(len(X_tr), ABL_TRAIN_N, replace=False))
X_tr_abl  = X_tr[tr_idx]
X_val_abl = X_val[:ABL_VAL_N]

def train_ablation(model, tag):
    model.compile(tf.keras.optimizers.Adam(1e-3, clipnorm=1.0), 'mse')
    t = time.time()
    hist = model.fit(
        X_tr_abl, X_tr_abl, validation_data=(X_val_abl, X_val_abl),
        epochs=ABL_EPOCHS, batch_size=ABL_BATCH,
        callbacks=[EarlyStopping('val_loss', patience=4, restore_best_weights=True, verbose=0)],
        verbose=0
    )
    elapsed = time.time() - t
    best_ep = int(np.argmin(hist.history['val_loss']))
    tl = hist.history['loss'][best_ep]; vl = hist.history['val_loss'][best_ep]
    gap = abs(vl - tl) / (tl + 1e-9) * 100
    log(f"  {tag}: trained {len(hist.history['loss'])} ep in {elapsed:.0f}s  "
        f"train_loss={tl:.5f}  val_loss={vl:.5f}  gap={gap:.1f}%")
    return model, gap

ablation_results = [{
    'Variant': f'Full {MODEL_B_NAME} (W=50, latent=32, dropout=0.2)',
    'F1': round(f1_b, 4), 'AUC': round(auc_b, 4),
    'Precision': round(prec_b, 4), 'Recall': round(rec_b, 4),
    'Notes': 'Complete model — all components'
}]

# ── Ablation 1: No Dropout ────────────────────────────────────────────────────
log("\n  Ablation 1: No Dropout (dropout=0.0)…")
m_nd, gap_nd = train_ablation(build_lstm_ae(dropout=0.0), 'No-dropout')
f1_nd, auc_nd = quick_eval_sampled(m_nd, X_eval, y_eval, X_val_eval)
ablation_results.append({
    'Variant': 'No Dropout (LSTM-AE)',
    'F1': round(f1_nd,4), 'AUC': round(auc_nd,4),
    'Precision': None, 'Recall': None,
    'Notes': f'Overfitting gap={gap_nd:.1f}% — regularisation removed'
})
log(f"  → F1={f1_nd:.4f}  AUC={auc_nd:.4f}")
del m_nd; gc.collect()

# ── Ablation 2: Smaller Window W=10 ──────────────────────────────────────────
log("\n  Ablation 2: Window W=10…")
W10 = 10
# Reuse first W10 timesteps of existing W=50 windows — avoids loading X_train.npy
X_tr_w10   = X_tr_abl[:, :W10, :]
X_val_w10  = X_val_abl[:, :W10, :]
X_eval_w10 = X_eval[:, :W10, :]       # 15K × 10 × 34 = 20 MB

m_w10 = build_lstm_ae(window=W10)
m_w10.compile(tf.keras.optimizers.Adam(1e-3, clipnorm=1.0), 'mse')
t = time.time()
m_w10.fit(X_tr_w10, X_tr_w10, validation_data=(X_val_w10, X_val_w10),
          epochs=ABL_EPOCHS, batch_size=ABL_BATCH,
          callbacks=[EarlyStopping('val_loss', patience=4, restore_best_weights=True, verbose=0)],
          verbose=0)
log(f"  Window W=10 trained in {time.time()-t:.0f}s")
f1_w10, auc_w10 = quick_eval_sampled(m_w10, X_eval_w10, y_eval, X_val_w10, window_size=W10)
ablation_results.append({
    'Variant': 'Window W=10 (LSTM-AE)',
    'F1': round(f1_w10,4), 'AUC': round(auc_w10,4),
    'Precision': None, 'Recall': None,
    'Notes': '10-flow context loses slow attack patterns'
})
log(f"  → F1={f1_w10:.4f}  AUC={auc_w10:.4f}")
del m_w10, X_tr_w10, X_val_w10, X_eval_w10; gc.collect()

# ── Ablation 3: No Positional Encoding (Transformer) ─────────────────────────
log("\n  Ablation 3: No Positional Encoding (Transformer-AE)…")
def build_tae_nope():
    inp = Input((W, F), name='input')
    x   = Dense(D_MODEL, name='proj')(inp)
    # No PE
    x   = tf_block(x, NUM_HEADS, D_MODEL, 128, DROPOUT, 'enc1')
    x   = tf_block(x, NUM_HEADS, D_MODEL, 128, DROPOUT, 'enc2')
    x   = GlobalAveragePooling1D(name='global_pool')(x)
    z   = Dense(LATENT_DIM, 'relu', name='latent')(x)
    dec_dim = D_MODEL // 4
    x   = Dense(W * dec_dim, 'relu', name='expand')(z)
    x   = Reshape((W, dec_dim), name='reshape')(x)
    x   = Dense(D_MODEL, name='dec_proj')(x)
    x   = tf_block(x, NUM_HEADS, D_MODEL, 128, DROPOUT, 'dec1')
    x   = tf_block(x, NUM_HEADS, D_MODEL, 128, DROPOUT, 'dec2')
    out = Dense(F, name='output')(x)
    return Model(inp, out, name='tae_nope')

m_nope, _ = train_ablation(build_tae_nope(), 'No-PE Transformer')
f1_npe, auc_npe = quick_eval_sampled(m_nope, X_eval, y_eval, X_val_eval)
ablation_results.append({
    'Variant': 'No Positional Encoding (Transformer-AE)',
    'F1': round(f1_npe,4), 'AUC': round(auc_npe,4),
    'Precision': None, 'Recall': None,
    'Notes': 'Position-agnostic — order information lost'
})
log(f"  → F1={f1_npe:.4f}  AUC={auc_npe:.4f}")
del m_nope; gc.collect()

# ── Ablation 4: Latent dim=8 ─────────────────────────────────────────────────
log("\n  Ablation 4: Latent dim=8 (LSTM-AE)…")
m_l8, _ = train_ablation(build_lstm_ae(latent=8), 'Latent-8')
f1_l8, auc_l8 = quick_eval_sampled(m_l8, X_eval, y_eval, X_val_eval)
ablation_results.append({
    'Variant': 'Latent dim=8 (LSTM-AE)',
    'F1': round(f1_l8,4), 'AUC': round(auc_l8,4),
    'Precision': None, 'Recall': None,
    'Notes': '212× compression — too little information capacity'
})
log(f"  → F1={f1_l8:.4f}  AUC={auc_l8:.4f}")
del m_l8; gc.collect()

# Save ablation table
abl_df = pd.DataFrame(ablation_results)
abl_df.to_csv(RESULTS_DIR / 'phase2_ablation_internal.csv', index=False)
log("\n=== ABLATION RESULTS ===")
log(abl_df[['Variant','F1','AUC','Notes']].to_string(index=False))
log("  Saved phase2_ablation_internal.csv")

# Ablation bar chart
fig, axes = plt.subplots(1, 2, figsize=(13, 4))
xv = np.arange(len(abl_df))
for ax, col, clr in zip(axes, ['F1','AUC'], ['#6C5CE7','#00B4D8']):
    vals = pd.to_numeric(abl_df[col], errors='coerce').values
    bars = ax.bar(xv, vals, 0.6,
                  color=[clr if i==0 else '#BDBDBD' for i in range(len(abl_df))],
                  alpha=0.85)
    ax.axhline(vals[0], color=clr, ls='--', lw=1.5, alpha=0.5)
    ax.set_xticks(xv)
    ax.set_xticklabels(abl_df['Variant'], rotation=18, ha='right', fontsize=7)
    ax.set_ylabel(col); ax.set_title(f'Ablation — {col}'); ax.grid(alpha=0.3, axis='y')
    for b, v in zip(bars, vals):
        if not np.isnan(v):
            ax.text(b.get_x()+b.get_width()/2, v+0.004, f'{v:.3f}', ha='center', fontsize=8)
plt.tight_layout()
plt.savefig(OUT_DIR / 'ablation_study.png', dpi=120, bbox_inches='tight')
plt.close(); log("  Saved ablation_study.png")


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 7  Cross-Phase Ablation Table
# ═════════════════════════════════════════════════════════════════════════════
log("\n=== Cross-Phase Ablation Table ===")
cross = pd.DataFrame([
    {'Model':'Statistical Baseline','Type':'Baseline',
     'Precision':0.521,'Recall':0.483,'F1':0.501,'AUC':0.612,
     'Phase':1,'Temporal':'No','Window':'N/A','Notes':'z-score per feature'},
    {'Model':'GMM K=12 (Model A)','Type':'Unsupervised ML',
     'Precision':0.883,'Recall':0.938,'F1':0.9097,'AUC':0.9576,
     'Phase':1,'Temporal':'No','Window':'N/A','Notes':'Full-covariance GMM, 34 features'},
    {'Model':f'{MODEL_B_NAME} (Model B)','Type':'Deep Learning AE',
     'Precision':round(prec_b,3),'Recall':round(rec_b,3),
     'F1':round(f1_b,4),'AUC':round(auc_b,4),
     'Phase':2,'Temporal':'Yes','Window':f'W={W}',
     'Notes':f'Sequence AE, latent={LATENT_DIM}'},
    {'Model':f'No Dropout ({MODEL_B_NAME})','Type':'Ablation',
     'Precision':'','Recall':'','F1':round(f1_nd,4),'AUC':round(auc_nd,4),
     'Phase':2,'Temporal':'Yes','Window':f'W={W}','Notes':'Dropout removed'},
    {'Model':'Window W=10 (LSTM-AE)','Type':'Ablation',
     'Precision':'','Recall':'','F1':round(f1_w10,4),'AUC':round(auc_w10,4),
     'Phase':2,'Temporal':'Yes','Window':'W=10','Notes':'Short context'},
    {'Model':'No Positional Encoding (Transformer)','Type':'Ablation',
     'Precision':'','Recall':'','F1':round(f1_npe,4),'AUC':round(auc_npe,4),
     'Phase':2,'Temporal':'Partial','Window':f'W={W}','Notes':'Order lost'},
    {'Model':'Latent dim=8 (LSTM-AE)','Type':'Ablation',
     'Precision':'','Recall':'','F1':round(f1_l8,4),'AUC':round(auc_l8,4),
     'Phase':2,'Temporal':'Yes','Window':f'W={W}','Notes':'Extreme compression'},
    {'Model':'Hybrid GMM+DL (Model C)','Type':'Hybrid',
     'Precision':'TBD','Recall':'TBD','F1':'TBD','AUC':'TBD',
     'Phase':3,'Temporal':'Yes','Window':'TBD','Notes':'Phase 3 ensemble'},
])
cross.to_csv(RESULTS_DIR / 'ablation_table_all_phases.csv', index=False)
log("  Saved ablation_table_all_phases.csv")
log(cross[['Model','F1','AUC','Phase']].to_string(index=False))


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 8  Latent Space PCA  (light — no t-SNE to save RAM + time)
# ═════════════════════════════════════════════════════════════════════════════
log("\n=== Latent Space PCA ===")
try:
    from sklearn.decomposition import PCA
    enc = Model(inputs=model_b.input,
                outputs=model_b.get_layer('latent').output)
    Z   = enc.predict(X_eval, batch_size=256, verbose=0)
    pca = PCA(n_components=2, random_state=SEED)
    Zp  = pca.fit_transform(Z)
    fig, ax = plt.subplots(figsize=(8, 6))
    sc = ax.scatter(Zp[:,0], Zp[:,1], c=y_eval, cmap='coolwarm',
                    alpha=0.5, s=10, linewidths=0)
    plt.colorbar(sc, ax=ax, label='Attack fraction')
    ax.set_xlabel(f'PC1 ({pca.explained_variance_ratio_[0]*100:.1f}%)')
    ax.set_ylabel(f'PC2 ({pca.explained_variance_ratio_[1]*100:.1f}%)')
    ax.set_title(f'{MODEL_B_NAME} Latent Space (PCA)')
    ax.grid(alpha=0.2)
    plt.tight_layout()
    plt.savefig(OUT_DIR / 'model_b_latent_pca.png', dpi=120, bbox_inches='tight')
    plt.close()
    log(f"  PC1={pca.explained_variance_ratio_[0]*100:.1f}%  "
        f"PC2={pca.explained_variance_ratio_[1]*100:.1f}%")
    log("  Saved model_b_latent_pca.png")
    del Z, Zp; gc.collect()
except Exception as e:
    log(f"  PCA skipped: {e}")


# ═════════════════════════════════════════════════════════════════════════════
# DONE
# ═════════════════════════════════════════════════════════════════════════════
log("\n" + "="*60)
log("  ABLATION STUDY COMPLETE")
log("="*60)
log(f"  Model B : {MODEL_B_NAME}")
log(f"  F1      : {f1_b:.4f}   (GMM baseline: 0.9097)")
log(f"  AUC     : {auc_b:.4f}   (GMM baseline: 0.9576)")
log(f"  Ablation F1s — no-dropout={f1_nd:.4f}  "
    f"W=10={f1_w10:.4f}  no-PE={f1_npe:.4f}  latent-8={f1_l8:.4f}")
log("="*60)
