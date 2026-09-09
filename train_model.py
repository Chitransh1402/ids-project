"""Train the baseline and calibrated models for SCCA-IDS.

Artifacts created in model/:
  ids_model.pkl              Original Random Forest; used by SHAP later.
  calibrated_ids_model.pkl   Isotonic-calibrated classifier; used for probability.
  encoders.pkl, scaler.pkl   Existing preprocessing artifacts.
  feature_cols.pkl           Exact ordered 41-feature input schema.
  global_top3.pkl            Top three RF feature indices for later SHAP scoring.
"""

from pathlib import Path

import joblib
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.frozen import FrozenEstimator
from sklearn.metrics import accuracy_score, brier_score_loss, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

from preprocess import preprocess


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
MODEL_DIR = BASE_DIR / "model"
MODEL_DIR.mkdir(exist_ok=True)

FEATURE_COLS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
]
CSV_COLS = FEATURE_COLS + ['label', 'difficulty']


def main():
    df_all = pd.read_csv(DATA_DIR / 'KDDTrain+.txt', names=CSV_COLS)
    df_test = pd.read_csv(DATA_DIR / 'KDDTest+.txt', names=CSV_COLS)

    # 60% model training, 20% calibration, 20% untouched test data.
    labels = df_all['label'].astype(str).str.strip().ne('normal')
    df_train, df_cal = train_test_split(
        df_all,
        test_size=0.25,
        random_state=42,
        stratify=labels,
    )

    # Fit encoders/scaler only on the RF-training split. preprocess() writes the
    # existing encoders.pkl and scaler.pkl files used by app.py.
    X_train, y_train, encoders, scaler = preprocess(df_train, fit=True)
    X_cal, y_cal, _, _ = preprocess(df_cal, fit=False, encoders=encoders, scaler=scaler)
    X_test, y_test, _, _ = preprocess(df_test, fit=False, encoders=encoders, scaler=scaler)

    rf_model = RandomForestClassifier(
        n_estimators=300,
        random_state=42,
        class_weight='balanced',
        n_jobs=-1,
    )
    print('Training Random Forest...')
    rf_model.fit(X_train, y_train)

    print('Fitting isotonic calibration on the held-out calibration split...')
    calibrated_model = CalibratedClassifierCV(
        estimator=FrozenEstimator(rf_model),
        method='isotonic',
    )
    calibrated_model.fit(X_cal, y_cal)

    raw_predictions = rf_model.predict(X_test)
    # Do not assume the attack class is always probability column 1.  In this
    # project, sklearn sorts the labels as ['attack', 'normal'].
    attack_index = list(calibrated_model.classes_).index('attack')
    calibrated_probabilities = calibrated_model.predict_proba(X_test)[:, attack_index]
    calibrated_predictions = calibrated_model.predict(X_test)
    y_test_attack = (y_test == 'attack').astype(int)

    print(f'\nRandom Forest accuracy: {accuracy_score(y_test, raw_predictions):.4f}')
    print(f'Calibrated model accuracy: {accuracy_score(y_test, calibrated_predictions):.4f}')
    print(f'Calibrated Brier score: {brier_score_loss(y_test_attack, calibrated_probabilities):.4f}')
    print('Calibrated model class order:', list(calibrated_model.classes_))
    print('\nCalibrated classification report:')
    print(classification_report(y_test, calibrated_predictions))
    print('Confusion matrix:')
    print(confusion_matrix(y_test, calibrated_predictions))

    global_top3 = rf_model.feature_importances_.argsort()[::-1][:3].tolist()
    joblib.dump(rf_model, MODEL_DIR / 'ids_model.pkl')
    joblib.dump(calibrated_model, MODEL_DIR / 'calibrated_ids_model.pkl')
    joblib.dump(FEATURE_COLS, MODEL_DIR / 'feature_cols.pkl')
    joblib.dump(global_top3, MODEL_DIR / 'global_top3.pkl')

    print('\nSaved: ids_model.pkl, calibrated_ids_model.pkl, feature_cols.pkl, global_top3.pkl')
    print('Top three global RF features:', [FEATURE_COLS[index] for index in global_top3])


if __name__ == '__main__':
    main()
