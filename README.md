# 🛡️ Cloud-Based Intelligent Intrusion Detection System

> Final Year B.Tech Project — Network Security · Machine Learning · Cloud Deployment

A real-time network intrusion detection system trained on the **NSL-KDD dataset** using a **Random Forest classifier**, served via a **Flask REST API**, and monitored through a **Streamlit dashboard** with login, live charts, and attack logging.

---

## 📐 Architecture

```
CSV Log Upload  (Streamlit Dashboard)
        │
        ▼
  Preprocessing  ──► encode categoricals, StandardScaler
        │
        ▼
  Random Forest Model  ──► Binary: Normal / Attack
        │
        ▼
  Flask REST API  (/predict endpoint)
        │
        ▼
  Dashboard + Alerts + Attack Log
        │
        ▼
  Cloud Deployment  (Render / Docker)
```

---

## 📁 Project Structure

```
ids-project/
├── app.py                  # Flask REST API
├── dashboard.py            # Streamlit dashboard (with login)
├── train_model.py          # Model training script
├── preprocess.py           # Feature engineering & encoding
├── logger.py               # Shared attack logger
├── create_demo_files.py    # Generate demo CSVs
├── check_data.py           # Dataset inspection utility
├── test_preprocess.py      # Preprocessing unit tests
│
├── model/
│   ├── ids_model.pkl       # Trained Random Forest
│   ├── encoders.pkl        # Category→integer mappings
│   └── scaler.pkl          # StandardScaler
│
├── data/
│   ├── KDDTrain+.txt       # NSL-KDD training set
│   ├── KDDTest+.txt        # NSL-KDD test set
│   └── index.html          # Dataset documentation
│
├── demo/
│   ├── normal_traffic.csv  # 10 normal sample rows
│   ├── attack_traffic.csv  # 10 attack sample rows
│   └── mixed_traffic.csv   # Mixed sample for demo
│
├── alerts.log              # Runtime attack log
├── Dockerfile              # Docker image for Flask API
├── docker-compose.yml      # Local multi-service setup
├── render.yaml             # Render.com deployment config
└── requirements.txt        # Pinned Python dependencies
```

---

## ⚙️ Tech Stack

| Layer        | Technology                        |
|--------------|-----------------------------------|
| Dataset      | NSL-KDD (KDDTrain+ / KDDTest+)    |
| ML Model     | Random Forest (scikit-learn)      |
| API Backend  | Flask 3.0                         |
| Dashboard    | Streamlit 1.35                    |
| Deployment   | Docker · Render.com               |
| Language     | Python 3.11                       |

---

## 🚀 Quick Start (Local)

### 1. Clone & install

```bash
git clone <your-repo-url>
cd ids-project
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Train the model (skip if model/ folder already exists)

```bash
python train_model.py
```

This reads `data/KDDTrain+.txt`, trains the Random Forest, and saves:
- `model/ids_model.pkl`
- `model/encoders.pkl`
- `model/scaler.pkl`

### 3. Start the Flask API

```bash
python app.py
# → Running on http://localhost:5000
```

### 4. Start the Streamlit dashboard

```bash
streamlit run dashboard.py
# → Running on http://localhost:8501
```

### 5. Test with demo data

Upload any file from the `demo/` folder in the dashboard to see predictions.

**Dashboard login:**
| Username | Password    |
|----------|-------------|
| admin    | ids@2024    |
| user     | network123  |

---

## 🐳 Docker (Local)

```bash
# Build & run both services
docker-compose up --build

# API  → http://localhost:5000
# Dashboard → http://localhost:8501
```

---

## ☁️ Render Deployment

1. Push your project to a GitHub repository.
2. Go to [render.com](https://render.com) → **New** → **Blueprint**.
3. Connect your repo — Render detects `render.yaml` automatically.
4. After `ids-api` deploys, copy its URL (e.g. `https://ids-api.onrender.com`).
5. Set that URL as the `API_URL` environment variable on the `ids-dashboard` service.
6. Both services will be live with HTTPS.

---

## 🔌 API Reference

### `GET /health`
```json
{ "status": "running", "model": "RandomForest-IDS" }
```

### `POST /predict`
**Request body:** JSON object with all 41 KDD network features.

**Response:**
```json
{
  "prediction": "attack",
  "alert": true
}
```

---

## 📊 Model Performance

Trained on NSL-KDD (`KDDTrain+.txt`), evaluated on `KDDTest+.txt`:

| Metric    | Value     |
|-----------|-----------|
| Accuracy  | ~99%      |
| Classifier| Random Forest (300 trees, balanced class weights) |
| Features  | 41 network connection features |
| Labels    | Binary: `normal` / `attack`    |

---

## 📦 Modules (for Viva)

| Module | Description |
|--------|-------------|
| 1 — Dataset Collection | NSL-KDD benchmark dataset with 41 features |
| 2 — Preprocessing | Label encoding, StandardScaler normalization |
| 3 — ML Detection Engine | Random Forest Classifier (300 estimators) |
| 4 — Cloud API | Flask REST endpoint (`/predict`, `/health`) |
| 5 — Dashboard & Alerts | Streamlit UI, pie chart, attack log, login |
| 6 — Cloud Deployment | Docker + Render.com deployment |

---

## 👨‍💻 Author

B.Tech Final Year Project — Computer Science / IT  
Made with the assistance of Claude AI (Anthropic)
