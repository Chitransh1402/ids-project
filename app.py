from pathlib import Path
import os

import joblib
import pandas as pd
from flask import Flask, jsonify, request

from preprocess import preprocess
from shap_scorer import score_prediction


BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "model"

app = Flask(__name__)

# Load preprocessing artifacts and SCCA-IDS models.
calibrated_model = joblib.load(MODEL_DIR / "calibrated_ids_model.pkl")
encoders = joblib.load(MODEL_DIR / "encoders.pkl")
scaler = joblib.load(MODEL_DIR / "scaler.pkl")
feature_cols = joblib.load(MODEL_DIR / "feature_cols.pkl")


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400

    missing = [column for column in feature_cols if column not in data]
    if missing:
        return jsonify({
            "error": "Missing required features",
            "missing": missing,
        }), 400

    try:
        # Build one-row input in the exact training schema.
        row = {column: data[column] for column in feature_cols}
        input_df = pd.DataFrame([row])
        input_df["label"] = "normal"

        # Apply the existing encoder and scaler artifacts.
        X_scaled, _, _, _ = preprocess(
            input_df,
            fit=False,
            encoders=encoders,
            scaler=scaler,
        )

        # Calibrated attack probability.
        probabilities = calibrated_model.predict_proba(X_scaled)[0]
        class_names = list(calibrated_model.classes_)
        attack_index = class_names.index("attack")
        attack_probability = float(probabilities[attack_index])

        prediction = str(calibrated_model.predict(X_scaled)[0])

        # SHAP consistency and top feature explanations.
        shap_result = score_prediction(X_scaled)

        confidence_index = (
            attack_probability
            * shap_result["shap_consistency"]
            * 100.0
        )

        if prediction == "normal":
            tier = "NORMAL"
        elif confidence_index >= 70:
            tier = "HIGH"
        elif confidence_index >= 40:
            tier = "MEDIUM"
        else:
            tier = "LOW"

        return jsonify({
            "prediction": prediction,
            "alert": prediction == "attack",
            "attack_probability": round(attack_probability, 6),
            "shap_consistency": round(
                shap_result["shap_consistency"], 6
            ),
            "confidence_index": round(confidence_index, 2),
            "tier": tier,
            "top_features": shap_result["top_features"],
        })

    except Exception as exc:
        app.logger.exception("Prediction failed")
        return jsonify({
            "error": "Prediction failed",
            "detail": str(exc),
        }), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "running",
        "model": "SCCA-IDS",
        "features": len(feature_cols),
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)