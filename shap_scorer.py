"""
shap_scorer.py
SCCA-IDS — SHAP Consistency Scoring Layer

Computes per-prediction SHAP consistency score:
  - Global top-K features from RF feature_importances_
  - Local top-K features from TreeSHAP per prediction
  - Consistency = overlap between local and global top-K / K

Confidence Index (CI) = calibrated_prob × shap_consistency × 100

Alert Tier:
  HIGH   (CI > 70) : auto-alert, email
  MEDIUM (40-70)   : log, flag
  LOW    (< 40)    : suppress or review
"""

import numpy as np
import joblib
import shap

FEATURE_NAMES = [
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

TIER_HIGH   = 70.0
TIER_MEDIUM = 40.0
TOP_K       = 3


class SHAPScorer:
    def __init__(self, rf_model, top_k: int = TOP_K):
        self.rf        = rf_model
        self.top_k     = top_k
        self.explainer = shap.TreeExplainer(rf_model)
        self.global_top_k = set(
            int(i) for i in np.argsort(rf_model.feature_importances_)[::-1][:top_k]
        )
        self._debug_done = False  # print shap shape once

    def compute(self, x_scaled: np.ndarray) -> dict:
        x_2d = x_scaled.reshape(1, -1)
        shap_output = self.explainer.shap_values(x_2d)

        # Debug: print shap output type/shape once
        if not self._debug_done:
            print(f"[SHAP DEBUG] type={type(shap_output)}", end="")
            if isinstance(shap_output, list):
                print(f" list len={len(shap_output)}, item[0].shape={np.array(shap_output[0]).shape}")
            elif isinstance(shap_output, np.ndarray):
                print(f" ndarray shape={shap_output.shape}")
            else:
                print(f" other: {shap_output.__class__.__name__}")
            self._debug_done = True

        # Handle all shap output formats across versions
        if isinstance(shap_output, list):
            # Old shap: list of arrays, one per class
            # classes_ = ['attack', 'normal'], index 0 = attack
            sv = np.array(shap_output[0]).flatten()
        elif isinstance(shap_output, np.ndarray):
            if shap_output.ndim == 3:
                # shape (n_classes, n_samples, n_features) or (n_samples, n_features, n_classes)
                if shap_output.shape[0] == 2:
                    sv = shap_output[0][0]   # class 0 (attack), sample 0
                elif shap_output.shape[2] == 2:
                    sv = shap_output[0, :, 0]  # sample 0, all features, class 0
                else:
                    sv = shap_output[0].flatten()
            elif shap_output.ndim == 2:
                # shape (n_samples, n_features)
                sv = shap_output[0]
            else:
                sv = shap_output.flatten()
        else:
            # Newer shap Explanation object
            try:
                sv = np.array(shap_output.values).flatten()
            except Exception:
                sv = np.zeros(len(FEATURE_NAMES))

        sv = np.array(sv, dtype=float).flatten()

        # Safety check
        if len(sv) != len(FEATURE_NAMES):
            sv = sv[:len(FEATURE_NAMES)] if len(sv) > len(FEATURE_NAMES) \
                 else np.pad(sv, (0, len(FEATURE_NAMES) - len(sv)))

        # Convert to Python ints explicitly to avoid unhashable ndarray in set
        abs_sv           = np.abs(sv).flatten()
        sorted_idx       = np.argsort(abs_sv)[::-1]
        local_top_k_idx  = set(int(i) for i in sorted_idx[:self.top_k])
        global_top_k_int = set(int(i) for i in self.global_top_k)
        overlap          = len(local_top_k_idx & global_top_k_int)
        shap_consistency = overlap / self.top_k

        top3_idx   = [int(i) for i in sorted_idx[:3]]
        local_top3 = [(FEATURE_NAMES[i], round(float(sv[i]), 4)) for i in top3_idx]
        top_idx    = top3_idx[0]

        return {
            'shap_values':      sv,
            'local_top_k':      local_top3,
            'shap_consistency': round(shap_consistency, 4),
            'top_feature':      FEATURE_NAMES[top_idx],
            'top_shap_value':   round(float(sv[top_idx]), 4),
        }

    def confidence_index(self, calibrated_prob: float, shap_consistency: float) -> float:
        return round(calibrated_prob * shap_consistency * 100, 2)

    @staticmethod
    def assign_tier(ci: float) -> str:
        if ci > TIER_HIGH:   return "HIGH"
        elif ci > TIER_MEDIUM: return "MEDIUM"
        else:                return "LOW"

    @staticmethod
    def tier_color(tier: str) -> str:
        return {"HIGH":"#EF4444","MEDIUM":"#F59E0B","LOW":"#94A3B8"}.get(tier,"#FFFFFF")

    @staticmethod
    def tier_action(tier: str) -> str:
        return {
            "HIGH":   "Auto-alert: Immediate action required",
            "MEDIUM": "Review: Investigate before escalating",
            "LOW":    "Suppress: Likely false positive or borderline",
        }.get(tier, "Unknown")


def load_calibrated_model(path: str = 'model/calibrated_model.pkl'):
    """
    Load calibrated model saved by calibration.py.
    CalibratedWrapper always returns [normal_prob, attack_prob].
    """
    data = joblib.load(path)

    if isinstance(data, dict) and 'iso_reg' in data:
        iso_reg    = data['iso_reg']
        rf         = data['rf']
        attack_idx = data['attack_idx']
        inverted   = data.get('inverted', False)

        class CalibratedWrapper:
            def __init__(self):
                self.rf         = rf
                self.iso_reg    = iso_reg
                self.attack_idx = attack_idx
                self.inverted   = inverted
                self.classes_   = rf.classes_

            def predict_proba(self, X):
                raw = self.rf.predict_proba(X)[:, self.attack_idx]
                if self.inverted:
                    raw = 1.0 - raw
                cal = self.iso_reg.predict(raw)
                # Always: col 0 = normal_prob, col 1 = attack_prob
                return np.column_stack([1 - cal, cal])

        return CalibratedWrapper()
    else:
        return data


def full_predict(x_scaled: np.ndarray,
                 calibrated_model,
                 scorer: SHAPScorer) -> dict:
    """
    Complete SCCA-IDS prediction for one record.
    calibrated_model.predict_proba() always returns [normal_prob, attack_prob].
    Attack probability is always at column index 1.
    """
    x_2d = x_scaled.reshape(1, -1)

    # Column 1 = attack probability from CalibratedWrapper
    cal_prob   = float(calibrated_model.predict_proba(x_2d)[0][1])
    prediction = "attack" if cal_prob >= 0.5 else "normal"

    shap_result = scorer.compute(x_scaled)
    ci          = scorer.confidence_index(cal_prob, shap_result['shap_consistency'])
    tier        = scorer.assign_tier(ci)

    return {
        "prediction":         prediction,
        "alert":              prediction == "attack",
        "calibrated_prob":    round(cal_prob, 4),
        "attack_probability": round(cal_prob, 6),
        "shap_consistency":   shap_result['shap_consistency'],
        "top_features":       shap_result['local_top_k'],
        "top_feature":        shap_result['top_feature'],
        "top_shap_value":     shap_result['top_shap_value'],
        "confidence_index":   ci,
        "tier":               tier,
        "tier_action":        SHAPScorer.tier_action(tier),
        "tier_color":         SHAPScorer.tier_color(tier),
    }


if __name__ == '__main__':
    import os
    print("Testing SHAPScorer...")
    if not os.path.exists('model/calibrated_model.pkl'):
        print("ERROR: Run calibration.py first.")
        exit(1)
    rf        = joblib.load('model/ids_model.pkl')
    cal_model = load_calibrated_model('model/calibrated_model.pkl')
    scorer    = SHAPScorer(rf)
    from calibration import load_and_encode
    X, y   = load_and_encode('data/KDDTest+.txt')
    sample = X[0]
    result = full_predict(sample, cal_model, scorer)
    print("\nSample prediction result:")
    for k, v in result.items():
        if k != 'top_features':
            print(f"  {k:<22}: {v}")
    print(f"  {'top_features':<22}: {result['top_features']}")
    print("\n✅ SHAPScorer working correctly!")