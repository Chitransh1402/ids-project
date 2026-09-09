"""
federated_train.py
Simulates Federated Learning on NSL-KDD dataset.

Architecture:
  - 3 clients (Hospital, Bank, Telecom) each get a partition of KDDTrain+
  - Each client trains a local Random Forest model
  - FedAvg aggregates decision tree leaf values across all clients
  - Global federated model is evaluated on KDDTest+
  - Results compared against the original centralized model
"""

import pandas as pd
import numpy as np
import joblib
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

# ── Column names ──────────────────────────────────────────────────────────────
COLS = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes',
    'land','wrong_fragment','urgent','hot','num_failed_logins','logged_in',
    'num_compromised','root_shell','su_attempted','num_root','num_file_creations',
    'num_shells','num_access_files','num_outbound_cmds','is_host_login',
    'is_guest_login','count','srv_count','serror_rate','srv_serror_rate',
    'rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate',
    'srv_diff_host_rate','dst_host_count','dst_host_srv_count',
    'dst_host_same_srv_rate','dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate',
    'dst_host_serror_rate','dst_host_srv_serror_rate',
    'dst_host_rerror_rate','dst_host_srv_rerror_rate','label','difficulty'
]

FEATURE_COLS = COLS[:41]

PROTOCOL_MAP = {'tcp':0,'udp':1,'icmp':2}
SERVICE_MAP  = {s:i for i,s in enumerate([
    'http','ftp','smtp','ssh','domain','ftp_data','other','eco_i','mtp',
    'telnet','finger','pop_3','nntp','imap4','courier','time','whois','csnet_ns',
    'pm_dump','ctf','nnsp','bgp','IRC','Z39_50','ldap','sunrpc','iso_tsap',
    'X11','discard','eco_i','login','shell','sql_net','hostnames','supdup',
    'link','systat','daytime','auth','gopher','uucp','remote_job','netstat',
    'pop_2','domain_u','ntp_u','exec','printer','efs','http_443','rje',
    'klogin','vmnet','harvest','echo','tftp_u','http_8001','urh_i','red_i',
    'urp_i','X11','smtp','private','mtp','http','ftp','other','aol','tim_i',
    'pm_dump','name','netbios_ssn','netbios_dgm','netbios_ns','kshell','uucp_path',
    'icmp','irc','nnsp','IRC','supdup','bgp','nntp','csnet_ns','Z39_50','sql_net',
    'gopher','finger','pop_2','rje','auth','remote_job','echo','discard',
    'uucp','netstat','login','shell','printer','efs','vmnet','hostnames',
    'iso_tsap','urh_i','ntp_u','domain_u','red_i','tftp_u','urp_i','http_443',
    'http_8001','aol','tim_i','harvest','klogin','kshell','name',
    'netbios_ssn','netbios_dgm','netbios_ns','uucp_path','sunrpc','whois',
    'pm_dump','ctf','courier','ssh'
])}
FLAG_MAP = {'SF':0,'S0':1,'REJ':2,'RSTO':3,'RSTR':4,'SH':5,'S1':6,'S2':7,'S3':8,'OTH':9,'RSTOS0':10}

CLIENT_NAMES = ["Hospital Network", "Banking System", "Telecom Provider"]


def encode_features(df):
    """Apply manual encoding to categorical features."""
    df = df.copy()
    df['protocol_type'] = df['protocol_type'].apply(lambda x: PROTOCOL_MAP.get(str(x).strip(), 0))
    df['service']       = df['service'].apply(lambda x: SERVICE_MAP.get(str(x).strip(), 0))
    df['flag']          = df['flag'].apply(lambda x: FLAG_MAP.get(str(x).strip(), 0))
    df['label']         = df['label'].apply(lambda x: 'normal' if str(x).strip() == 'normal' else 'attack')
    for col in FEATURE_COLS:
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
    return df


def load_dataset(path):
    """Load and preprocess the NSL-KDD dataset."""
    df = pd.read_csv(path, names=COLS)
    df = encode_features(df)
    X = df[FEATURE_COLS].values
    y = df['label'].values
    return X, y


def evaluate_model(model, X_test, y_test):
    """Return accuracy, precision, recall, f1, confusion matrix."""
    y_pred = model.predict(X_test)
    cm = confusion_matrix(y_test, y_pred, labels=['normal','attack'])
    return {
        'accuracy':  round(accuracy_score(y_test, y_pred) * 100, 2),
        'precision': round(precision_score(y_test, y_pred, pos_label='attack', zero_division=0) * 100, 2),
        'recall':    round(recall_score(y_test, y_pred, pos_label='attack', zero_division=0) * 100, 2),
        'f1':        round(f1_score(y_test, y_pred, pos_label='attack', zero_division=0) * 100, 2),
        'cm':        cm.tolist()
    }


def fedavg(client_models, n_estimators=100):
    """
    FedAvg for Random Forest:
    Collect all decision trees from all client models and form
    a new combined Random Forest — simulating weight aggregation.
    Each client contributes n_estimators/num_clients trees.
    """
    print("\n[FedAvg] Aggregating client models...")
    all_estimators = []
    trees_per_client = n_estimators // len(client_models)

    for i, model in enumerate(client_models):
        # Take a subset of trees from each client
        selected = model.estimators_[:trees_per_client]
        all_estimators.extend(selected)
        print(f"  Client {i+1} contributed {len(selected)} trees")

    # Build the aggregated global model
    global_model = RandomForestClassifier(
        n_estimators=len(all_estimators),
        class_weight='balanced',
        random_state=42
    )
    # Manually set estimators (FedAvg aggregation)
    global_model.estimators_         = all_estimators
    global_model.n_estimators        = len(all_estimators)
    global_model.n_features_in_      = client_models[0].n_features_in_
    global_model.n_outputs_          = client_models[0].n_outputs_
    global_model.classes_            = client_models[0].classes_
    global_model.n_classes_          = client_models[0].n_classes_

    print(f"  Global model has {len(all_estimators)} aggregated trees total")
    return global_model


def run_federated_training():
    """Main federated training pipeline."""
    print("=" * 60)
    print("FEDERATED LEARNING SIMULATION — NSL-KDD IDS")
    print("=" * 60)

    # Load data
    print("\n[1] Loading NSL-KDD dataset...")
    X_train, y_train = load_dataset('data/KDDTrain+.txt')
    X_test,  y_test  = load_dataset('data/KDDTest+.txt')
    print(f"    Training samples : {len(X_train)}")
    print(f"    Test samples     : {len(X_test)}")

    # Load the original centralized scaler
    scaler = joblib.load('model/scaler.pkl')
    X_train_scaled = scaler.transform(X_train)
    X_test_scaled  = scaler.transform(X_test)

    # ── Step 1: Split into 3 client partitions ────────────────────────────────
    print("\n[2] Splitting training data into 3 client partitions...")
    n = len(X_train_scaled)
    indices = np.random.RandomState(42).permutation(n)
    splits  = np.array_split(indices, 3)

    client_data = []
    for i, idx in enumerate(splits):
        cx, cy = X_train_scaled[idx], y_train[idx]
        n_attack = np.sum(cy == 'attack')
        n_normal = np.sum(cy == 'normal')
        print(f"    {CLIENT_NAMES[i]}: {len(cx)} samples "
              f"(normal={n_normal}, attack={n_attack})")
        client_data.append((cx, cy))

    # ── Step 2: Local training on each client ─────────────────────────────────
    print("\n[3] Local training on each client (100 trees each)...")
    client_models  = []
    client_metrics = []

    for i, (cx, cy) in enumerate(client_data):
        print(f"\n    Training {CLIENT_NAMES[i]}...")
        local_model = RandomForestClassifier(
            n_estimators=100,
            class_weight='balanced',
            random_state=42
        )
        local_model.fit(cx, cy)
        metrics = evaluate_model(local_model, X_test_scaled, y_test)
        client_models.append(local_model)
        client_metrics.append(metrics)
        print(f"    Accuracy: {metrics['accuracy']}% | "
              f"Precision: {metrics['precision']}% | "
              f"Recall: {metrics['recall']}% | "
              f"F1: {metrics['f1']}%")

    # ── Step 3: FedAvg aggregation ────────────────────────────────────────────
    print("\n[4] FedAvg aggregation...")
    global_model    = fedavg(client_models, n_estimators=100)
    global_metrics  = evaluate_model(global_model, X_test_scaled, y_test)
    print(f"\n    [Global Model] Accuracy: {global_metrics['accuracy']}% | "
          f"Precision: {global_metrics['precision']}% | "
          f"Recall: {global_metrics['recall']}% | "
          f"F1: {global_metrics['f1']}%")

    # ── Step 4: Load centralized model for comparison ─────────────────────────
    print("\n[5] Loading centralized model for comparison...")
    central_model   = joblib.load('model/ids_model.pkl')
    central_metrics = evaluate_model(central_model, X_test_scaled, y_test)
    print(f"    [Centralized]   Accuracy: {central_metrics['accuracy']}% | "
          f"Precision: {central_metrics['precision']}% | "
          f"Recall: {central_metrics['recall']}% | "
          f"F1: {central_metrics['f1']}%")

    # ── Step 5: Save results ──────────────────────────────────────────────────
    os.makedirs('federated_model', exist_ok=True)
    joblib.dump(global_model, 'federated_model/federated_model.pkl')

    results = {
        'client_names':    CLIENT_NAMES,
        'client_metrics':  client_metrics,
        'global_metrics':  global_metrics,
        'central_metrics': central_metrics,
        'n_clients':       3,
        'trees_per_client': 100,
    }
    joblib.dump(results, 'federated_model/federated_results.pkl')

    print("\n[6] Saved:")
    print("    federated_model/federated_model.pkl")
    print("    federated_model/federated_results.pkl")
    print("\n✅ Federated training complete!")
    return results


if __name__ == '__main__':
    results = run_federated_training()

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"\n{'Model':<25} {'Accuracy':>10} {'Precision':>10} {'Recall':>10} {'F1':>10}")
    print("-" * 65)
    for i, (name, m) in enumerate(zip(CLIENT_NAMES, results['client_metrics'])):
        print(f"{'Client '+str(i+1)+' ('+name+')':<25} {m['accuracy']:>9}% {m['precision']:>9}% {m['recall']:>9}% {m['f1']:>9}%")
    print(f"{'Federated (FedAvg)':<25} {results['global_metrics']['accuracy']:>9}% "
          f"{results['global_metrics']['precision']:>9}% "
          f"{results['global_metrics']['recall']:>9}% "
          f"{results['global_metrics']['f1']:>9}%")
    print(f"{'Centralized (Baseline)':<25} {results['central_metrics']['accuracy']:>9}% "
          f"{results['central_metrics']['precision']:>9}% "
          f"{results['central_metrics']['recall']:>9}% "
          f"{results['central_metrics']['f1']:>9}%")