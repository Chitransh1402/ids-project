"""
calibration.py
SCCA-IDS — Calibration Layer

Applies isotonic regression calibration to the Random Forest model.
Computes Expected Calibration Error (ECE) and Brier Score.
Saves the calibrated model for use by the Flask API.
"""

import numpy as np
import pandas as pd
import joblib
import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.metrics import brier_score_loss


# ── Column names ──────────────────────────────────────────────────────────────
COLS = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes',
    'land','wrong_fragment','urgent','hot','num_failed_logins','logged_in',
    'num_compromised','root_shell','su_attempted','num_root',
    'num_file_creations','num_shells','num_access_files','num_outbound_cmds',
    'is_host_login','is_guest_login','count','srv_count','serror_rate',
    'srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate',
    'diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count',
    'dst_host_same_srv_rate','dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate',
    'dst_host_serror_rate','dst_host_srv_serror_rate',
    'dst_host_rerror_rate','dst_host_srv_rerror_rate','label','difficulty'
]
FEATURE_COLS = COLS[:41]

PROTOCOL_MAP = {'tcp':0, 'udp':1, 'icmp':2}
FLAG_MAP     = {
    'SF':0,'S0':1,'REJ':2,'RSTO':3,'RSTR':4,
    'SH':5,'S1':6,'S2':7,'S3':8,'OTH':9,'RSTOS0':10
}


def _build_service_map():
    services = [
        'http','ftp','smtp','ssh','domain','ftp_data','other','eco_i','mtp',
        'telnet','finger','pop_3','nntp','imap4','courier','time','whois',
        'csnet_ns','pm_dump','ctf','nnsp','bgp','IRC','Z39_50','ldap',
        'sunrpc','iso_tsap','X11','discard','login','shell','sql_net',
        'hostnames','supdup','link','systat','daytime','auth','gopher','uucp',
        'remote_job','netstat','pop_2','domain_u','ntp_u','exec','printer',
        'efs','http_443','rje','klogin','vmnet','harvest','echo','tftp_u',
        'http_8001','urh_i','red_i','urp_i','smtp','private','name',
        'netbios_ssn','netbios_dgm','netbios_ns','kshell','uucp_path','icmp',
        'aol','tim_i','mtp'
    ]
    return {s: i for i, s in enumerate(services)}

SERVICE_MAP = _build_service_map()


def load_and_encode(path: str):
    """Load NSL-KDD file, encode features, return X (scaled) and y."""
    df = pd.read_csv(path, names=COLS)
    df['protocol_type'] = df['protocol_type'].apply(
        lambda x: PROTOCOL_MAP.get(str(x).strip(), 0))
    df['service'] = df['service'].apply(
        lambda x: SERVICE_MAP.get(str(x).strip(), 0))
    df['flag'] = df['flag'].apply(
        lambda x: FLAG_MAP.get(str(x).strip(), 0))
    # Keep labels as strings — match what RF was trained on
    df['label'] = df['label'].apply(
        lambda x: 'normal' if str(x).strip() == 'normal' else 'attack')
    for col in FEATURE_COLS:
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
    X = df[FEATURE_COLS].values
    y = df['label'].values
    scaler = joblib.load('model/scaler.pkl')
    X_scaled = scaler.transform(X)
    return X_scaled, y


def get_attack_prob(model, X):
    """
    Get probability of 'attack' class.
    - For raw RF: attack may be at index 0 or 1 depending on class order.
    - For CalibratedWrapper: always returns [normal, attack] so attack = col 1.
    """
    classes = list(model.classes_)
    if 'attack' in classes:
        attack_idx = classes.index('attack')
    elif 1 in classes:
        attack_idx = classes.index(1)
    else:
        attack_idx = 1
    return model.predict_proba(X)[:, attack_idx]


def get_calibrated_attack_prob(calibrated_model, X):
    """
    Get attack probability from CalibratedWrapper.
    The wrapper ALWAYS returns [normal_prob, attack_prob],
    so attack probability is always column 1.
    """
    return calibrated_model.predict_proba(X)[:, 1]


def compute_ece(y_true, y_prob, n_bins: int = 10) -> float:
    """
    Expected Calibration Error (ECE).
    y_true: any label format (string 'attack'/'normal', or binary 0/1)
    y_prob: float array of attack probabilities
    """
    # Always convert to binary safely
    y_arr = np.array(y_true)
    y_bin = np.where(y_arr == 'attack', 1, 0).astype(int)

    bins = np.linspace(0, 1, n_bins + 1)
    ece  = 0.0
    n    = len(y_bin)
    for i in range(n_bins):
        lo, hi = bins[i], bins[i + 1]
        mask   = (y_prob >= lo) & (y_prob < hi)
        if mask.sum() == 0:
            continue
        avg_conf = y_prob[mask].mean()
        avg_acc  = y_bin[mask].mean()
        ece     += (mask.sum() / n) * abs(avg_conf - avg_acc)
    return round(ece, 4)


def fit_calibration(X_cal, y_cal):
    """
    Fit isotonic regression calibration on the calibration split.
    Works on all sklearn versions without cv='prefit'.
    """
    from sklearn.isotonic import IsotonicRegression

    rf         = joblib.load('model/ids_model.pkl')
    classes    = list(rf.classes_)
    attack_idx = classes.index('attack')
    normal_idx = 1 - attack_idx  # opposite index

    print(f"  RF classes: {classes}, attack_idx={attack_idx}")

    # Get raw RF probabilities for attack class on calibration set
    raw_probs = rf.predict_proba(X_cal)[:, attack_idx]

    # Binary labels: 1=attack, 0=normal
    y_bin = np.where(np.array(y_cal) == 'attack', 1, 0).astype(float)

    print(f"  Raw prob stats: min={raw_probs.min():.4f} max={raw_probs.max():.4f} mean={raw_probs.mean():.4f}")
    print(f"  Label stats: attack_rate={y_bin.mean():.4f}")

    # Correlation check — if negative, probs are inverted
    correlation = np.corrcoef(raw_probs, y_bin)[0, 1]
    print(f"  Prob-label correlation: {correlation:.4f}")

    if correlation < 0:
        # Invert probabilities so they align with labels
        print("  ⚠️  Negative correlation — inverting probabilities for calibration")
        fit_probs = 1.0 - raw_probs
    else:
        fit_probs = raw_probs

    # Fit isotonic regression: maps fit_probs → calibrated_prob
    iso_reg = IsotonicRegression(out_of_bounds='clip', increasing=True)
    iso_reg.fit(fit_probs, y_bin)

    # Verify calibration improved
    cal_probs  = iso_reg.predict(fit_probs)
    ece_raw    = np.mean(np.abs(fit_probs - y_bin))
    ece_cal    = np.mean(np.abs(cal_probs - y_bin))
    print(f"  MAE before calibration: {ece_raw:.4f}")
    print(f"  MAE after  calibration: {ece_cal:.4f}")

    # Save everything needed for inference
    joblib.dump({
        'iso_reg':    iso_reg,
        'rf':         rf,
        'attack_idx': attack_idx,
        'inverted':   correlation < 0,
        'classes':    classes,
    }, 'model/calibrated_model.pkl')

    print("  Saved: model/calibrated_model.pkl (isotonic regressor)")

    # Return wrapper for pipeline evaluation
    class CalibratedWrapper:
        def __init__(self, rf, iso_reg, attack_idx, inverted):
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
            return np.column_stack([1 - cal, cal])

    return CalibratedWrapper(rf, iso_reg, attack_idx, correlation < 0)


def save_calibrated_model(calibrated_model):
    """Save the calibrated model to model/ directory."""
    os.makedirs('model', exist_ok=True)
    joblib.dump(calibrated_model, 'model/calibrated_model.pkl')
    print("  Saved: model/calibrated_model.pkl")


def plot_reliability_diagram(
        y_true, y_prob_raw, y_prob_cal,
        save_path: str = 'model/calibration_curve.png'):
    """
    Plot reliability diagram comparing uncalibrated vs calibrated probabilities.
    The diagonal line = perfect calibration.
    """
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    fig.suptitle('Reliability Diagram: RF Calibration Quality',
                 fontsize=14, fontweight='bold')

    for ax, probs, title, color in zip(
            axes,
            [y_prob_raw, y_prob_cal],
            ['Uncalibrated RF', 'After Isotonic Calibration'],
            ['#EF4444', '#22C55E']):

        fraction_pos, mean_pred = calibration_curve(
            y_true, probs, n_bins=10, strategy='uniform')

        ax.plot([0, 1], [0, 1], 'k--', label='Perfect calibration', lw=1.5)
        ax.plot(mean_pred, fraction_pos, 's-', color=color,
                label=title, lw=2, markersize=8)
        ax.fill_between(mean_pred, mean_pred, fraction_pos,
                        alpha=0.15, color=color)
        ax.set_xlabel('Mean Predicted Probability', fontsize=11)
        ax.set_ylabel('Fraction of Positives (Actual)', fontsize=11)
        ax.set_title(title, fontsize=12, fontweight='bold')
        ax.legend(fontsize=10)
        ax.set_xlim(0, 1); ax.set_ylim(0, 1)
        ax.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Saved reliability diagram: {save_path}")


def run_calibration_pipeline(data_path: str = 'data/KDDTrain+.txt'):
    """
    Full calibration pipeline:
    1. Load data
    2. Split into train / calibration / test (60/20/20)
    3. Fit isotonic calibration on calibration split
    4. Compute ECE and Brier Score before and after
    5. Save calibrated model
    6. Save reliability diagram
    """
    print("=" * 60)
    print("SCCA-IDS — CALIBRATION PIPELINE")
    print("=" * 60)

    print("\n[1] Loading and encoding data...")
    X, y = load_and_encode(data_path)
    print(f"    Total samples: {len(X)}")

    # 60/20/20 split with fixed seed for reproducibility
    np.random.seed(42)
    idx      = np.random.permutation(len(X))
    n        = len(X)
    n_train  = int(n * 0.60)
    n_cal    = int(n * 0.20)

    train_idx = idx[:n_train]
    cal_idx   = idx[n_train:n_train + n_cal]
    test_idx  = idx[n_train + n_cal:]

    X_cal, y_cal   = X[cal_idx],   y[cal_idx]
    X_test, y_test = X[test_idx],  y[test_idx]

    print(f"    Calibration split: {len(X_cal)} samples")
    print(f"    Test split:        {len(X_test)} samples")

    # ── Before calibration ────────────────────────────────────────────────────
    print("\n[2] Computing metrics BEFORE calibration...")
    rf = joblib.load('model/ids_model.pkl')
    print(f"    RF classes: {rf.classes_}")  # debug: confirm class order
    y_prob_raw = get_attack_prob(rf, X_test)

    # Convert labels for brier score
    y_bin = np.where(np.array(y_test) == 'attack', 1, 0).astype(int)
    ece_before   = compute_ece(y_test, y_prob_raw)
    brier_before = round(brier_score_loss(y_bin, y_prob_raw), 4)
    print(f"    ECE   (before): {ece_before}")
    print(f"    Brier (before): {brier_before}")

    # ── Fit calibration ───────────────────────────────────────────────────────
    print("\n[3] Fitting isotonic regression calibration...")
    calibrated = fit_calibration(X_cal, y_cal)

    # ── After calibration ─────────────────────────────────────────────────────
    print("\n[4] Computing metrics AFTER calibration...")
    # CalibratedWrapper always returns [normal_prob, attack_prob] → col 1
    y_prob_cal = get_calibrated_attack_prob(calibrated, X_test)

    ece_after   = compute_ece(y_test, y_prob_cal)
    brier_after = round(brier_score_loss(y_bin, y_prob_cal), 4)
    print(f"    ECE   (after):  {ece_after}")
    print(f"    Brier (after):  {brier_after}")

    ece_reduction   = round((ece_before - ece_after) / ece_before * 100, 1)
    brier_reduction = round((brier_before - brier_after) / brier_before * 100, 1)
    print(f"\n    ECE reduction:   {ece_reduction}%")
    print(f"    Brier reduction: {brier_reduction}%")

    # Convert string labels to binary for calibration curve
    y_bin_test = np.where(np.array(y_test) == 'attack', 1, 0).astype(int)
    # y_prob_raw: from RF using correct attack index
    # y_prob_cal: from wrapper col 1 (always attack)
    print("\n[5] Saving calibrated model and diagram...")
    # Note: calibrated model already saved inside fit_calibration()
    plot_reliability_diagram(y_bin_test, y_prob_raw, y_prob_cal)

    results = {
        'ece_before':      ece_before,
        'ece_after':       ece_after,
        'ece_reduction':   ece_reduction,
        'brier_before':    brier_before,
        'brier_after':     brier_after,
        'brier_reduction': brier_reduction,
        'n_cal':           len(X_cal),
        'n_test':          len(X_test),
    }
    joblib.dump(results, 'model/calibration_results.pkl')
    print("  Saved: model/calibration_results.pkl")

    print("\n✅ Calibration pipeline complete!")
    print(f"\n{'Metric':<20} {'Before':>10} {'After':>10} {'Reduction':>12}")
    print("-" * 55)
    print(f"{'ECE':<20} {ece_before:>10} {ece_after:>10} {ece_reduction:>10}%")
    print(f"{'Brier Score':<20} {brier_before:>10} {brier_after:>10} {brier_reduction:>10}%")

    return results


if __name__ == '__main__':
    results = run_calibration_pipeline()