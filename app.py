"""
app.py — SCCA-IDS Flask REST API

Endpoints:
  GET  /health   — API status check
  POST /predict  — Standard binary prediction (backward compatible)
  POST /predict_scca — Full SCCA-IDS prediction with CI + tier + SHAP
"""

from flask import Flask, request, jsonify
import joblib
import pandas as pd
import numpy as np
import os

app = Flask(__name__)

# ── Load models ───────────────────────────────────────────────────────────────
rf_model  = joblib.load('model/ids_model.pkl')
encoders  = joblib.load('model/encoders.pkl')
scaler    = joblib.load('model/scaler.pkl')

# Load calibrated model if available
CALIBRATED_AVAILABLE = os.path.exists('model/calibrated_model.pkl')
if CALIBRATED_AVAILABLE:
    from shap_scorer import SHAPScorer, full_predict, load_calibrated_model
    calibrated_model = load_calibrated_model('model/calibrated_model.pkl')
    scorer = SHAPScorer(rf_model)
    print("✅ SCCA-IDS: Calibrated model + SHAP scorer loaded")
else:
    print("⚠️  Calibrated model not found — run calibration.py first")
    calibrated_model = None
    scorer = None

FEATURE_COLS = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes',
    'land','wrong_fragment','urgent','hot','num_failed_logins','logged_in',
    'num_compromised','root_shell','su_attempted','num_root',
    'num_file_creations','num_shells','num_access_files','num_outbound_cmds',
    'is_host_login','is_guest_login','count','srv_count','serror_rate',
    'srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate',
    'diff_srv_rate','srv_diff_host_rate','dst_host_count',
    'dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate',
    'dst_host_serror_rate','dst_host_srv_serror_rate',
    'dst_host_rerror_rate','dst_host_srv_rerror_rate'
]


def preprocess(data: dict) -> np.ndarray:
    """Encode and scale a single record dict → 1D numpy array."""
    df = pd.DataFrame([data])
    for col in ['protocol_type', 'service', 'flag']:
        mapping = encoders[col]
        df[col] = df[col].apply(
            lambda x: mapping.get(str(x).strip(), 0))
    for col in FEATURE_COLS:
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
    return scaler.transform(df[FEATURE_COLS].values)[0]


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status":               "running",
        "model":                "RandomForest-IDS",
        "scca_available":       CALIBRATED_AVAILABLE,
        "calibrated_model":     CALIBRATED_AVAILABLE,
    })


@app.route('/predict', methods=['POST'])
def predict():
    """Standard prediction — backward compatible with existing dashboard."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON payload"}), 400
    try:
        x = preprocess(data)
        x_2d = x.reshape(1, -1)
        prediction = rf_model.predict(x_2d)[0]
        return jsonify({
            "prediction": prediction,
            "alert":      bool(prediction == "attack"),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/predict_scca', methods=['POST'])
def predict_scca():
    """
    SCCA-IDS full prediction.
    Returns: prediction + calibrated_prob + shap_consistency +
             confidence_index + tier + tier_action + top_features
    Falls back to standard predict if calibration not available.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON payload"}), 400

    try:
        x = preprocess(data)

        if not CALIBRATED_AVAILABLE:
            pred = rf_model.predict(x.reshape(1, -1))[0]
            prob = float(rf_model.predict_proba(x.reshape(1, -1))[0][1])
            return jsonify({
                "prediction":       pred,
                "alert":            pred == "attack",
                "calibrated_prob":  round(prob, 4),
                "attack_probability": round(prob, 6),
                "shap_consistency": None,
                "confidence_index": round(prob * 100, 2),
                "tier":             "HIGH" if prob > 0.7 else ("MEDIUM" if prob > 0.4 else "LOW"),
                "tier_action":      "Run calibration.py for full SCCA-IDS",
                "top_features":     [],
                "top_feature":      "calibration_not_run",
                "scca_mode":        False,
            })

        result = full_predict(x, calibrated_model, scorer)
        result["scca_mode"] = True
        return jsonify(result)

    except Exception as e:
        import traceback
        print(f"ERROR in /predict_scca: {e}")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route('/calibration_results', methods=['GET'])
def calibration_results():
    """Return calibration metrics (ECE, Brier score) for dashboard display."""
    path = 'model/calibration_results.pkl'
    if not os.path.exists(path):
        return jsonify({"error": "Calibration not run yet. Run calibration.py first."}), 404
    results = joblib.load(path)
    return jsonify(results)


if __name__ == '__main__':
    port  = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)