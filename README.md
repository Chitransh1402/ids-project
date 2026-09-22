#  SCCA-IDS: Confidence-Calibrated Intrusion Detection System

> **B.Tech Final Year Project** — Information Technology  
> G.H. Raisoni College of Engineering, Nagpur | Academic Year 2025-2026

A Cloud-Based Intelligent Intrusion Detection System featuring **isotonic probability calibration**, **SHAP consistency scoring**, **Federated Learning simulation**, and **RAG-powered AI explanations** — deployed on Render Cloud.

---

## 🔴 Live Demo

| Service | URL |
|---|---|
| 🖥️ Dashboard | https://ids-dashboard-g2az.onrender.com |
| 🔧 Flask API | https://ids-project2-o.onrender.com |
| ❤️ Health Check | https://ids-project2-o.onrender.com/health |

**Login:** `admin / ids@2024` (Admin) · `user / network123` (Viewer)

> ⚠️ Free tier — first load may take ~50 seconds to wake up.

---

## 👥 Team

| Name | Role |
|---|---|
| Chitransh Shrivastava | ML Pipeline, SCCA-IDS, Deployment |
| Yash Jain | Dashboard, RAG AI, Testing |
| Yug Agrawal | Federated Learning, API Development |
| Dhiraj Patle | Dataset Processing, Documentation |
 
**Department:** Information Technology, GHRCE Nagpur

---

## 🔬 Research Contribution — SCCA-IDS

This project introduces **SCCA-IDS** (SHAP-Calibrated Confidence-Aware IDS) — a novel framework that combines:

1. **Isotonic Probability Calibration** — corrects raw RF probability outputs so that a predicted confidence of 80% genuinely corresponds to 80% actual attack rate (ECE reduced from 0.0724 → 0.0005, a **99.3% improvement**)

2. **SHAP Consistency Scoring** — for every prediction, compares local per-prediction SHAP feature importance against global model feature importance; consistency score = overlap between local and global top-3 features

3. **Unified Confidence Index (CI)** — `CI = calibrated_prob × shap_consistency × 100`

4. **Alert Tiering System:**
   - 🔴 **HIGH** (CI > 70): Auto-alert, immediate action
   - 🟡 **MEDIUM** (40 < CI ≤ 70): Review recommended
   - ⚪ **LOW** (CI ≤ 40): Suppress, likely false positive

**Result on NSL-KDD mixed traffic (30 records):**
- HIGH tier precision: **100%** (6/6 true attacks)
- MEDIUM tier precision: **100%** (9/9 true attacks)
- LOW tier: **100% suppression** (15/15 normal — zero false positives escalated)
- Alert burden reduced by **50%** while maintaining full recall

---

## 🏗️ System Architecture

```
CSV Log Upload  (Streamlit Dashboard)
        │
        ▼
  Preprocessing  ──► encode categoricals, StandardScaler
        │
        ▼
  Random Forest Classifier (300 trees)
        │
        ├──► [Calibration Layer]
        │     Isotonic Regression → calibrated_prob
        │
        ├──► [SHAP Layer]
        │     TreeSHAP → local top-3 features
        │     vs global top-3 → consistency score
        │
        ▼
  Confidence Index = calibrated_prob × shap_consistency × 100
        │
        ▼
  Alert Tier: HIGH / MEDIUM / LOW
        │
        ▼
  Dashboard + Email Alert + Attack Log
        │
        ▼
  Cloud Deployment (Docker + Render)
```

---

## 📁 Project Structure

```
ids-project2.O/
├── app.py                    # Flask REST API (/predict, /predict_scca, /health)
├── dashboard.py              # Streamlit dashboard (8 tabs)
├── train_model.py            # RF model training
├── preprocess.py             # Feature encoding + scaling
├── calibration.py            # SCCA-IDS: isotonic calibration + ECE computation
├── shap_scorer.py            # SCCA-IDS: SHAP consistency + CI + tier assignment
├── federated_train.py        # Federated Learning: FedAvg across 3 clients
├── knowledge_base.py         # RAG: cybersecurity knowledge documents
├── rag_engine.py             # RAG: Groq LLM + retrieval (threat explainer, chatbot, report)
├── logger.py                 # Attack logging utility
├── create_demo_files.py      # Generate demo CSVs
│
├── model/
│   ├── ids_model.pkl         # Trained Random Forest
│   ├── encoders.pkl          # Categorical encoders
│   ├── scaler.pkl            # StandardScaler
│   ├── calibrated_model.pkl  # Isotonic regression calibration
│   ├── calibration_curve.png # Reliability diagram
│   └── calibration_results.pkl
│
├── federated_model/
│   ├── federated_model.pkl   # FedAvg aggregated model
│   └── federated_results.pkl # Per-client + global metrics
│
├── demo/
│   ├── normal_traffic.csv
│   ├── attack_traffic.csv
│   └── mixed_traffic.csv
│
├── data/                     # NSL-KDD dataset (gitignored)
│   ├── KDDTrain+.txt
│   └── KDDTest+.txt
│
├── Dockerfile                # Flask API container
├── docker-compose.yml        # Local multi-service setup
├── render.yaml               # Render cloud deployment config
├── requirements.txt
└── .env.example              # Environment variable template
```

---

## ⚙️ Tech Stack

| Layer | Technology |
|---|---|
| Dataset | NSL-KDD (KDDTrain+ / KDDTest+) |
| ML Model | Random Forest (scikit-learn, 300 trees) |
| Calibration | IsotonicRegression (scikit-learn) |
| Explainability | SHAP (TreeExplainer) |
| API Backend | Flask |
| Dashboard | Streamlit |
| RAG / AI | Groq API (Llama 3.1-8b-instant) |
| Email Alerts | Gmail SMTP |
| Deployment | Docker + Render Cloud |
| Version Control | Git + GitHub |
| Language | Python 3.11 |

---

## 🚀 Local Setup

### 1. Clone & Install

```bash
git clone https://github.com/Chitransh1402/ids-project2.O.git
cd ids-project2.O
python -m venv .venv
.\.venv\Scripts\Activate.ps1        # Windows
# source .venv/bin/activate         # Linux/Mac
pip install -r requirements.txt
```

### 2. Environment Variables

Create a `.env` file:

```env
API_URL=http://localhost:5000
SMTP_SENDER=your_gmail@gmail.com
SMTP_PASSWORD=your_gmail_app_password
ALERT_TO=recipient@gmail.com
GROQ_API_KEY=gsk_your_groq_key
```

### 3. Download NSL-KDD Dataset

Download from https://www.unb.ca/cic/datasets/nsl.html and place in `data/`:
```
data/KDDTrain+.txt
data/KDDTest+.txt
```

### 4. Train the Model

```bash
python train_model.py
```

### 5. Run SCCA-IDS Calibration (one-time)

```bash
python calibration.py
```

Expected output:
```
ECE   (before): 0.0724
ECE   (after):  0.0005
ECE reduction:  99.3%
Saved: model/calibrated_model.pkl
```

### 6. Start Flask API

```bash
python app.py
# ✅ SCCA-IDS: Calibrated model + SHAP scorer loaded
# Running on http://localhost:5000
```

### 7. Start Streamlit Dashboard

```bash
streamlit run dashboard.py
# Running on http://localhost:8501
```

### 8. Test with Demo Files

Upload any file from `demo/` folder in the dashboard.

---

## 🐳 Docker (Local)

```bash
docker-compose up --build
# API  → http://localhost:5000
# Dashboard → http://localhost:8501
```

---

## ☁️ Render Deployment

1. Push to GitHub
2. Go to render.com → New → Blueprint → connect repo
3. Render detects `render.yaml` automatically
4. Set environment variables in Render dashboard:
   - `API_URL`, `GROQ_API_KEY`, `SMTP_PASSWORD`, `SMTP_SENDER`, `ALERT_TO`
5. Deploy

---

## 🔌 API Reference

### `GET /health`
```json
{
  "status": "running",
  "model": "RandomForest-IDS",
  "scca_available": true,
  "calibrated_model": true
}
```

### `POST /predict`
Standard binary prediction (backward compatible).

**Request:** JSON with 41 NSL-KDD features  
**Response:**
```json
{"prediction": "attack", "alert": true}
```

### `POST /predict_scca`
Full SCCA-IDS prediction with confidence scoring.

**Request:** JSON with 41 NSL-KDD features  
**Response:**
```json
{
  "prediction": "attack",
  "alert": true,
  "calibrated_prob": 1.0,
  "shap_consistency": 1.0,
  "confidence_index": 100.0,
  "tier": "HIGH",
  "tier_action": "Auto-alert: Immediate action required",
  "top_feature": "src_bytes",
  "top_features": [["src_bytes", 0.42], ["count", 0.18], ["dst_bytes", 0.09]]
}
```

### `GET /calibration_results`
Returns ECE and Brier Score before/after calibration.

---

## 📊 Dashboard Tabs

| Tab | Description |
|---|---|
| 📂 Analyze Traffic | Upload CSV, get standard predictions |
| 📊 Statistics & Metrics | Confusion matrix, accuracy, precision, recall, F1, charts |
| 📋 Attack Log | Timestamped attack log with tier labels |
| 🎯 SCCA-IDS | **Calibration metrics, reliability diagram, CI histogram, tier precision** |
| 🤝 Federated Learning | FedAvg simulation across 3 clients |
| 🔍 AI Threat Explainer | RAG-powered attack explanation |
| 💬 AI Chatbot | Ask anything about IDS/attacks |
| 📝 AI Report | Auto-generated security incident report |

---

## 📈 Model Performance

| Metric | Value |
|---|---|
| Accuracy | ~99% |
| Precision | ~99% |
| Recall | ~98% |
| F1 Score | ~98% |
| ECE (before calibration) | 0.0724 |
| **ECE (after calibration)** | **0.0005 (99.3% reduction)** |
| Brier Score (before) | 0.0148 |
| **Brier Score (after)** | **0.0021 (85.8% reduction)** |
| HIGH tier precision | **100%** |
| LOW tier false positive rate | **0%** |
| Alert burden reduction | **50%** |

---

## 🎓 SCCA-IDS Modules (for Viva)

| Module | Description |
|---|---|
| 1 — Dataset | NSL-KDD (125,973 train / 22,544 test records, 41 features) |
| 2 — Preprocessing | Categorical encoding + StandardScaler normalization |
| 3 — ML Engine | Random Forest Classifier (300 estimators, balanced weights) |
| 4 — Calibration | Isotonic regression on 20% calibration split |
| 5 — SHAP Scoring | TreeSHAP consistency between local and global feature importance |
| 6 — Confidence Index | CI = calibrated_prob × shap_consistency × 100 |
| 7 — Alert Tiering | HIGH / MEDIUM / LOW with tier-level precision measurement |
| 8 — Cloud API | Flask /predict and /predict_scca endpoints (Docker + Render) |
| 9 — Dashboard | Streamlit: 8 tabs, role-based auth, charts, reliability diagram |
| 10 — Federated Learning | FedAvg across 3 simulated clients (Hospital, Bank, Telecom) |
| 11 — RAG AI | Groq LLM + knowledge base: explainer, chatbot, report generator |

---

## 📚 References

1. Tavallaee et al. (2009) — NSL-KDD Dataset
2. Breiman (2001) — Random Forests
3. Revathi & Malathi (2013) — RF vs other classifiers on NSL-KDD
4. Khraisat et al. (2019) — Survey of IDS techniques
5. Pedregosa et al. (2011) — scikit-learn

---

## 📄 License

This project is submitted as a B.Tech final year academic project at G.H. Raisoni College of Engineering, Nagpur.

---

