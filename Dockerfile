# ── Stage: base ──────────────────────────────────────────────────────────────
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY app.py       .
COPY preprocess.py .
COPY logger.py    .
COPY model/       model/

# Expose Flask port
EXPOSE 5000

# Environment defaults (override at runtime)
ENV FLASK_DEBUG=false
ENV PORT=5000

# Run
CMD ["python", "app.py"]
