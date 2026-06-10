from flask import Flask, request, jsonify
import joblib
import pandas as pd
import numpy as np
import os

app = Flask(__name__)

model    = joblib.load('model/ids_model.pkl')
encoders = joblib.load('model/encoders.pkl')
scaler   = joblib.load('model/scaler.pkl')

FEATURE_COLS = [
    'duration','protocol_type','service','flag','src_bytes',
    'dst_bytes','land','wrong_fragment','urgent','hot',
    'num_failed_logins','logged_in','num_compromised','root_shell',
    'su_attempted','num_root','num_file_creations','num_shells',
    'num_access_files','num_outbound_cmds','is_host_login',
    'is_guest_login','count','srv_count','serror_rate',
    'srv_serror_rate','rerror_rate','srv_rerror_rate',
    'same_srv_rate','diff_srv_rate','srv_diff_host_rate',
    'dst_host_count','dst_host_srv_count','dst_host_same_srv_rate',
    'dst_host_diff_srv_rate','dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate','dst_host_serror_rate',
    'dst_host_srv_serror_rate','dst_host_rerror_rate',
    'dst_host_srv_rerror_rate'
]


@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON payload received"}), 400

    df = pd.DataFrame([data])

    for col in ['protocol_type', 'service', 'flag']:
        mapping = encoders[col]
        df[col] = df[col].apply(lambda x: mapping.get(str(x).strip(), 0))

    for col in FEATURE_COLS:
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

    df_scaled  = scaler.transform(df[FEATURE_COLS].values)
    prediction = model.predict(df_scaled)[0]

    return jsonify({
        "prediction": prediction,
        "alert": bool(prediction == "attack")
    })


@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "running", "model": "RandomForest-IDS"})


if __name__ == '__main__':
    port  = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)
