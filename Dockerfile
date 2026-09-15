# ── Stage: base ──────────────────────────────────────────────────────────────
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy ALL Python source files
COPY app.py           .
COPY preprocess.py    .
COPY logger.py        .
COPY calibration.py   .
COPY shap_scorer.py   .
COPY knowledge_base.py .
COPY rag_engine.py    .
COPY federated_train.py .

# Copy model directory (includes calibrated_model.pkl)
COPY model/           model/

# Expose Flask port
EXPOSE 5000

# Environment defaults (override at runtime)
ENV FLASK_DEBUG=false
ENV PORT=5000

# Run
CMD ["python", "app.py"]