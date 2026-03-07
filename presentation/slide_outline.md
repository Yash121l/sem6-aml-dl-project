# Presentation Slide Outline
## Adaptive Cyber-Physical Security — Phase 1 Results
**Format:** 10 slides · 10 minutes · Viva-ready

---

## Slide 1 — Title (0:00–0:30)

**Title:** Adaptive Cyber-Physical Security: Anomaly-Based Intrusion Detection

**Content:**
- Subtitle: Phase 1 — Classical ML Baseline (Model A)
- Team names
- Course: Advanced Machine Learning and Deep Learning, Semester 6
- Date: March 2026

**Visual:** Project logo or a network topology illustration.

**Speaker notes:**
"Good morning. This presentation covers Phase 1 of our three-phase project to build an
adaptive intrusion detection system for cyber-physical networks. In 10 minutes we will cover
our methodology, results, and what Phase 2 will tackle. Let's begin."

**Evaluator question:** "Why is this called 'adaptive'?"
**Model answer:** "The system adapts in two senses: first, it detects anomalies without
needing pre-labeled attack data, so it adapts to unseen threats. Second, we plan sliding-window
retraining in Phase 3 to handle concept drift as normal traffic evolves over time."

---

## Slide 2 — Problem Motivation (0:30–1:30)

**Title:** Why Anomaly Detection for Industrial Networks?

**Content:**
- Real-world incidents: Stuxnet (2010), Ukraine power grid (2015), Oldsmar water plant (2021)
- Key stat: ~68% of OT breaches involve techniques unseen at deployment time (Verizon DBIR 2023)
- Problem statement: Signature-based IDS is blind to zero-day attacks
- Our thesis: **Learn what normal looks like — flag everything else**

**Visual:**
- Timeline of high-profile ICS/CPS attacks on the left
- Diagram showing a zero-day attack bypassing a signature-based detector on the right

**Speaker notes:**
"In 2021 an attacker remotely accessed a Florida water treatment plant and attempted to
increase sodium hydroxide to dangerous levels. The IDS raised no alert because the technique
was novel. This is the zero-day problem. We cannot keep building rule databases fast enough.
The solution is to model normal behavior so accurately that any deviation is automatically
suspicious — whether we have seen the attack before or not."

**Evaluator questions:**
1. "How do you handle false positives in a safety-critical environment?"
**Answer:** "Our GMM achieves 88.2% precision — roughly 1 in 8 alarms is a false positive.
In Phase 3 we plan an alert-confirmation layer using Model B's temporal signal to reduce
false positives before operator notification."

2. "What makes CPS networks different from enterprise networks?"
**Answer:** "CPS networks run real-time deterministic protocols like Modbus and DNP3 with
highly repetitive, predictable traffic. This makes the normal manifold tighter, potentially
enabling more sensitive anomaly detection, but also means slow 'living off the land' attacks
that mimic polling are harder to distinguish."

---

## Slide 3 — Our Approach vs. Alternatives (1:30–2:30)

**Title:** Why One-Class Learning? The Case Against Alternatives

**Content — Comparison table:**

| Approach | Requires Attack Labels | Detects Zero-Day | Our Choice |
|----------|----------------------|-----------------|-----------|
| Signature-based (Snort) | Rule database | No | No |
| Supervised ML (Random Forest) | Yes, many examples | No | No |
| **Anomaly Detection (ours)** | **No** | **Yes** | **Yes** |

- **Key insight (highlight in bold):** "We train on 1.5M benign flows. We never see a single
  attack during training. Yet we detect 90.97% of attacks at test time."
- Analogy: "Like a bank fraud system that learns normal spending, not a list of known frauds."

**Visual:** Three boxes side by side; the third one glowing green.

**Speaker notes:**
"This is the most important conceptual slide. Spend time here. The evaluator will probe whether
you understand WHY anomaly detection is the right choice for this problem, not just that you
implemented it. The answer is always: we cannot enumerate future attack types, but we can
enumerate what normal looks like."

**Evaluator questions:**
1. "Couldn't you just use a semi-supervised approach with the labeled data you have?"
**Answer:** "Yes, and that is Model C in Phase 3. But establishing a purely unsupervised
baseline first is important: it measures how much information is in the normal distribution
alone, and any gains from adding labeled attack data can be attributed precisely to the
supervision signal."

2. "What is the train/test split protocol for anomaly detection — is it different from
   supervised learning?"
**Answer:** "Yes. The training set contains only benign flows; no attack examples are ever
shown to the model. The test set contains both benign and attack flows. Labels in the test set
are used only for evaluation metrics, never for training. This faithfully simulates a deployment
scenario where the model has never seen the attack class."

---

## Slide 4 — Dataset (2:30–3:00)

**Title:** CICIDS-2017 — What We're Working With

**Content:**
- 2.8M network flows, 80 features, 14 attack types, captured July 2017
- Features extracted by CICFlowMeter: packet-length stats, IAT, TCP flags, flow duration
- Data quality challenges:
  - Infinite values (zero-duration flows → division by zero in flow-rate features)
  - Extreme class imbalance: 80.9% benign
  - Small set of duplicate rows

**Visual:** Class distribution bar chart (`outputs/eda/plot1_class_distribution.png`)

**Speaker notes:**
"Keep this slide brief — 30 seconds. Establish what data we used and flag the known issues
that motivated our preprocessing choices. DoS Hulk alone has 172K flows; Web XSS has only 652.
This imbalance is why supervised learning would be unreliable and why anomaly detection is
preferred."

**Evaluator question:** "Why not use a more recent dataset?"
**Answer:** "CICIDS-2017 is the most widely benchmarked IDS dataset, enabling direct
comparison with prior work. We plan to evaluate on SWaT and BATADAL datasets targeting
CPS-specific attacks in Phase 3."

---

## Slide 5 — EDA Key Findings (3:00–4:30)

**Title:** What EDA Told Us — And How It Drove Every Preprocessing Decision

**Content — 3 plots with 1-sentence interpretations:**

1. **Feature skewness distribution** (`plot2_feature_distributions.png`):
   "Over 60% of features have |skew| > 1 → motivated log-transform."

2. **Correlation heatmap** (`plot3_correlation_heatmap.png`):
   "46 feature pairs with |r| > 0.95 → motivated correlation-based feature removal."

3. **t-SNE projection** (`plot8_tsne.png`):
   "Clear benign cluster in centre with attack peripheries → validates anomaly detection approach."

**Speaker notes:**
"Our EDA drove every single preprocessing decision. We did not randomly pick transformations;
each one is justified by what we found in the data. This is what distinguishes engineering
from guessing. The t-SNE plot is the key takeaway: if the normal data occupies a compact
region in feature space, a density model can learn its boundary. If normal and attack data
were completely mixed, no anomaly detector would work."

**Evaluator questions:**
1. "Why is the t-SNE result important for your methodology choice?"
**Answer:** "t-SNE showing distinct benign and attack clusters is empirical evidence that
the anomaly detection hypothesis holds on this dataset: the normal distribution is learnable
and compact. If they were inseparable we would need a different approach."

2. "Isn't t-SNE non-linear? Does the separation guarantee your linear-ish model will also
   separate them?"
**Answer:** "Good point. t-SNE shows geometric separability but does not imply linear
separability. The PCA plot also shows partial separation, suggesting non-trivial but
non-trivially-linear structure. Our GMM with full covariance handles non-axis-aligned
distributions, and the 95.76% AUC confirms it works well in practice."

---

## Slide 6 — Preprocessing Pipeline (4:30–5:30)

**Title:** The Leakage-Free Preprocessing Pipeline

**Content:**
- Architecture diagram (simplified version from `outputs/architecture_diagram_phase1.png`)
- Six steps listed with short justifications:
  1. Inf/NaN → median imputation
  2. IQR capping [q₀.₀₁, q₀.₉₉]
  3. Log transform: x' = log(1 + x) for |skew| > 1
  4. Feature engineering: 5 ratio/timing features
  5. RobustScaler: x̃ = (x − Q₂) / (Q₃ − Q₁)
  6. Correlation removal: drop if |r| > 0.95

**Highlight in red:** "FIT PARAMETERS ESTIMATED ON BENIGN TRAIN ONLY → APPLIED TO ALL"
(Use the NO DATA LEAKAGE BOUNDARY box from the diagram)

**Visual:** The architecture diagram, zoomed to the preprocessing row.

**Speaker notes:**
"The single most important engineering decision in this entire project is in red on this slide.
Every scaler, every IQR boundary, every correlation mask was computed using the benign
training set and then frozen. When we processed the test set, we used those frozen parameters.
If we had re-fit the scaler on the test set — even just to normalize it — we would have leaked
information about the test distribution into our preprocessing, and our metrics would be
artificially inflated. This is called data leakage and it is a very common mistake."

**Evaluator questions:**
1. "What would happen if you fit the RobustScaler on both train and test?"
**Answer:** "The scaler would encode test-set statistics (e.g., the median of attack flows)
into the normalization. At evaluation time, the attack flows would appear more 'normal'
than they truly are in deployment, inflating recall while hiding the true distribution shift.
Real deployment uses only train-time parameters."

2. "Why RobustScaler and not StandardScaler?"
**Answer:** "StandardScaler uses mean and standard deviation, which are strongly influenced
by extreme outliers. DoS Hulk flows, for example, have packet rates 1000× higher than normal.
Including them would inflate the standard deviation and compress the normal data into a tiny
range. RobustScaler uses median and interquartile range, which are robust to these outliers."

---

## Slide 7 — Models: Theory (5:30–6:30)

**Title:** Three Models — One Key Equation Each

**Content — Three columns:**

**Isolation Forest**
- Intuition: Anomalies are rare and easy to isolate in random partitions
- Score: s(x, n) = 2^{−E[h(x)] / c(n)}
- Best params: n_estimators=50, contamination=0.15, max_features=0.5
- Result: F1 = 61.4%, AUC = 80.3%

**One-Class SVM**
- Intuition: Find maximum-margin hypersphere enclosing normal data in kernel space
- Objective: min ½‖w‖² − ρ + (1/νn) Σ ξᵢ, s.t. ⟨w, φ(xᵢ)⟩ ≥ ρ − ξᵢ
- Best params: kernel=RBF, ν=0.2, γ=0.1
- Result: F1 = 75.9%, AUC = 87.2%

**GMM (Model A — selected)**
- Intuition: Model benign traffic as K Gaussian clusters; anomalies have low density
- Density: p(x) = Σ πₖ N(x | μₖ, Σₖ) → detect if log p(x) < τ
- Best params: K=12, covariance=full, threshold=11th percentile
- Result: **F1 = 90.97%, AUC = 95.76%**

**Visual:** Three boxes with formulas, GMM box highlighted in purple.

**Speaker notes:**
"Show that you understand the math, not just the sklearn API. For Isolation Forest:
a point that takes 3 splits to isolate is more anomalous than one that takes 20. For OCSVM:
we are finding the smallest hypersphere in kernel space that contains most training points.
For GMM: we model the density and flag low-probability samples. K=12 means we identified 12
benign traffic regimes — probably interactive web, DNS polling, bulk FTP, ICMP pings, etc."

**Evaluator questions:**
1. "Why does GMM outperform Isolation Forest by such a large margin?"
**Answer:** "Isolation Forest uses random partitions — it does not model the actual density
of normal data. GMM explicitly estimates the distribution as K Gaussian components, giving
it a richer, more calibrated anomaly score. Furthermore, Isolation Forest's contamination
hyperparameter sets a hard threshold on the fraction of anomalies, whereas GMM's percentile
threshold is more flexible."

2. "Why K=12 components? How did you choose this?"
**Answer:** "We swept K from 1 to 15 and selected the value that minimised the Bayesian
Information Criterion (BIC) on an 80,000-sample subsample of training data. BIC penalises
model complexity, preventing overfitting. Both BIC and AIC agreed on K=12."

---

## Slide 8 — Results (6:30–8:00)

**Title:** Results — Model A Achieves F1 = 90.97%, AUC = 95.76%

**Content:**

**Main results table:**
| Model | F1 | AUC-ROC |
|-------|----|---------|
| Statistical Baseline | 66.7% | 64.8% |
| Isolation Forest | 61.4% | 80.3% |
| One-Class SVM | 75.9% | 87.2% |
| **GMM (Model A)** | **90.97%** | **95.76%** |

**ROC curves:** (`outputs/models/plot09_model_comparison.png`)

**Per-attack detection rates (highlights):**
- High detection: DDoS (99.9%), FTP-Patator (98.9%), DoS Hulk (93.9%)
- Low detection: Web XSS (3.1%), Brute Force (9.9%)

**Visual:** Side by side — results table on left, ROC plot on right.

**Speaker notes:**
"Walk through numbers confidently. DDoS and large-volume DoS attacks are detected
almost perfectly because they produce flow statistics wildly outside the normal distribution
— high packet rates, extreme byte counts, degenerate IAT distributions. The GMM assigns them
extremely low log-likelihood scores. The failure cases are more interesting and are on the
next slide."

**Evaluator questions:**
1. "Your precision is 88.2% — that means 11.8% of alarms are false positives. Is that
   acceptable for production deployment?"
**Answer:** "In a high-stakes industrial environment, a 11.8% false positive rate would
generate alert fatigue. Our Phase 3 hybrid system plans to add a second-stage confirmation
using Model B's temporal evidence to verify alarms before surfacing them to operators.
That should bring the false positive rate below 2%."

2. "The GMM has much higher recall than Isolation Forest. Why?"
**Answer:** "Recall measures what fraction of actual attacks we detected. Isolation Forest's
contamination parameter was tuned to 15%, but the actual attack fraction in our test set is
~50%, so its threshold is miscalibrated. GMM's threshold is based on the 11th percentile of
in-distribution log-likelihoods, which adapts more naturally to the test distribution."

---

## Slide 9 — Failure Analysis (8:00–8:30)

**Title:** Where Model A Fails — And Why That Motivates Phase 2

**Content:**
- PCA failure analysis plot (`outputs/models/plot11_failure_analysis.png`)
- Table of high-miss-rate attack types:
  - Web XSS: 96.9% missed
  - Brute Force: 90.1% missed
  - DoS GoldenEye: 45.2% missed

**One clear statement in large text:**
> "Web application attacks send HTTP requests at normal human browsing rates. At the
> flow level, they look identical to benign traffic. Model A cannot detect them —
> **Model B will capture their temporal pattern.**"

**Visual:** PCA plot with false-negative flows highlighted red overlapping with the benign cluster.

**Speaker notes:**
"This is the most intellectually honest slide in the deck. We are telling the evaluator
exactly where our model fails and why. This demonstrates scientific maturity. The key insight
is that these attacks are slow by design — they operate at rates that blend into normal traffic.
No density model over individual flows can distinguish them. But an attacker issuing 100 login
attempts has a temporal pattern: 100 requests to /login with incrementing username fields in a
60-second window. An LSTM Autoencoder trained on sequences of consecutive flows will have high
reconstruction error for such patterns."

**Evaluator questions:**
1. "Could you have detected web attacks by adding application-layer features?"
**Answer:** "Yes, payload-level features like HTTP verb frequency, URL entropy, or response
code sequences would help. CICFlowMeter only provides network-layer and transport-layer
statistics. Phase 3 plans integration of application-layer feature extraction as an additional
input channel."

2. "Why is DoS GoldenEye harder than DoS Hulk for your model?"
**Answer:** "DoS Hulk is high-volume — it floods the server with many connections simultaneously,
producing extreme packet rates. GoldenEye is lower-volume, targeting HTTP Keep-Alive connections
to exhaust server threads with fewer packets. Fewer packets means less deviation from the normal
flow-level statistics that our GMM learned."

---

## Slide 10 — Phase 2 Plan (8:30–9:00)

**Title:** What's Next — Model B (Phase 2)

**Content:**
- Architecture diagram with Phase 2 component highlighted (`outputs/ablation_overview.png`)
- Phase 2 approach:
  - **LSTM Autoencoder** trained on sequences of N consecutive flows
  - Input: window of N flow feature vectors
  - Training: minimize reconstruction error on benign-only sequences
  - Detection: flag sequences with high reconstruction error
- Why this helps: temporal patterns of attacks differ from benign browsing sequences
- Ablation table (carry forward from Slide 8 with Phase 2 = TBD):

| Model | Phase | F1 | AUC |
|-------|-------|----|-----|
| GMM | Phase 1 | **90.97%** | **95.76%** |
| LSTM-AE / Transformer-AE | Phase 2 | TBD | TBD |
| Hybrid | Phase 3 | TBD | TBD |

**Speaker notes:**
"Keep this brief — 30 seconds. Leave the audience wanting more. The key message is:
we have a 90.97% F1 baseline. We know exactly what it misses and why. Phase 2 directly
targets those failure cases with a complementary architecture."

**Evaluator questions:**
1. "What sequence length will you use for the LSTM?"
**Answer:** "We plan to evaluate window sizes of N = 10, 20, 50 flows, selected by
reconstruction error on a validation benign set. Shorter windows capture burst patterns;
longer windows are needed for slow-rate attacks. We expect N≈20 to balance coverage and
computational cost."

2. "How will you combine Model A and Model B in Phase 3?"
**Answer:** "We plan a late-fusion approach: compute the GMM log-likelihood score and the
LSTM reconstruction error independently, then train a shallow meta-classifier (logistic
regression or a learned weighted sum) on a held-out validation set to produce a single
anomaly score. This allows each model to contribute its complementary signal."

---

## Summary Cheat Sheet

| Slide | Time | Key Takeaway |
|-------|------|-------------|
| 1. Title | 0:00 | Project intro |
| 2. Motivation | 0:30 | Zero-day problem is real and unsolved |
| 3. Approach | 1:30 | Anomaly detection = no attack labels needed |
| 4. Dataset | 2:30 | CICIDS-2017: 2.8M flows, 14 attacks |
| 5. EDA | 3:00 | Skewness + correlation → preprocessing decisions |
| 6. Preprocessing | 4:30 | 6 steps, ALL fit on benign train only |
| 7. Models | 5:30 | IF / OCSVM / GMM — one equation each |
| 8. Results | 6:30 | GMM: F1=90.97%, AUC=95.76% |
| 9. Failure | 8:00 | Web attacks evade — temporal model needed |
| 10. Phase 2 | 8:30 | LSTM-AE targets missed attacks |

**Top 3 viva questions to prepare:**
1. "Why anomaly detection and not supervised classification?" → Zero-day generalisation.
2. "What is data leakage and how did you prevent it?" → Fit only on benign train.
3. "Why GMM over Isolation Forest?" → Density estimation vs. path-length heuristic; BIC-selected K.
