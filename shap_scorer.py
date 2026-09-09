from pathlib import Path

import joblib
import numpy as np
import shap


BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "model"

RF_MODEL_PATH = MODEL_DIR / "ids_model.pkl"
GLOBAL_TOP3_PATH = MODEL_DIR / "global_top3.pkl"
FEATURE_COLS_PATH = MODEL_DIR / "feature_cols.pkl"


# Load the original Random Forest and saved SCCA artifacts.
rf_model = joblib.load(RF_MODEL_PATH)
global_top3 = set(joblib.load(GLOBAL_TOP3_PATH))
feature_cols = joblib.load(FEATURE_COLS_PATH)

# TreeSHAP is appropriate for Random Forest models.
explainer = shap.TreeExplainer(rf_model)


def _get_attack_shap_values(values):
    """Return one-dimensional SHAP values for the attack class."""
    shap_values = explainer.shap_values(values)

    # Older SHAP versions return a list: [normal_values, attack_values].
    if isinstance(shap_values, list):
        class_index = list(rf_model.classes_).index("attack")
        return np.asarray(shap_values[class_index][0], dtype=float)

    # Newer SHAP versions may return an ndarray.
    shap_values = np.asarray(shap_values)

    if shap_values.ndim == 3:
        class_index = list(rf_model.classes_).index("attack")
        return shap_values[0, :, class_index].astype(float)

    if shap_values.ndim == 2:
        return shap_values[0].astype(float)

    return shap_values.astype(float).reshape(-1)


def score_prediction(features):
    """
    Calculate SHAP consistency for one preprocessed 41-feature row.

    `features` may be a dictionary keyed by feature name or an ordered
    list/array matching feature_cols.
    """
    if isinstance(features, dict):
        values = np.asarray(
            [[features[column] for column in feature_cols]],
            dtype=float,
        )
    else:
        values = np.asarray(features, dtype=float).reshape(1, -1)

    if values.shape[1] != len(feature_cols):
        raise ValueError(
            f"Expected {len(feature_cols)} features, received {values.shape[1]}"
        )

    shap_row = _get_attack_shap_values(values)
    local_top3 = set(np.argsort(np.abs(shap_row))[::-1][:3].tolist())

    consistency = len(local_top3.intersection(global_top3)) / 3.0

    top_indices = np.argsort(np.abs(shap_row))[::-1][:3]
    top_features = [
        {
            "feature": feature_cols[index],
            "shap_value": float(shap_row[index]),
        }
        for index in top_indices
    ]

    return {
        "shap_consistency": float(consistency),
        "local_top3": sorted(local_top3),
        "top_features": top_features,
    }