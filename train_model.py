import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)
import joblib
from preprocess import preprocess

# Column names
cols = ['duration','protocol_type','service','flag','src_bytes','dst_bytes',
        'land','wrong_fragment','urgent','hot','num_failed_logins','logged_in',
        'num_compromised','root_shell','su_attempted','num_root',
        'num_file_creations','num_shells','num_access_files',
        'num_outbound_cmds','is_host_login','is_guest_login','count',
        'srv_count','serror_rate','srv_serror_rate','rerror_rate',
        'srv_rerror_rate','same_srv_rate','diff_srv_rate',
        'srv_diff_host_rate','dst_host_count','dst_host_srv_count',
        'dst_host_same_srv_rate','dst_host_diff_srv_rate',
        'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate',
        'dst_host_serror_rate','dst_host_srv_serror_rate',
        'dst_host_rerror_rate','dst_host_srv_rerror_rate',
        'label','difficulty']

# Load datasets
df_train = pd.read_csv('data/KDDTrain+.txt', names=cols)
df_test = pd.read_csv('data/KDDTest+.txt', names=cols)

# Preprocess training data
X_train, y_train, encoders, scaler = preprocess(
    df_train,
    fit=True
)

# Preprocess test data
X_test, y_test, _, _ = preprocess(
    df_test,
    fit=False,
    encoders=encoders,
    scaler=scaler
)

# Improved Random Forest
model = RandomForestClassifier(
    n_estimators=300,
    random_state=42,
    class_weight="balanced",
    n_jobs=-1
)

print("Training model...")
model.fit(X_train, y_train)

# Predictions
preds = model.predict(X_test)

# Accuracy
accuracy = accuracy_score(y_test, preds)

print("\nAccuracy:")
print(f"{accuracy:.4f}")

# Classification Report
print("\nClassification Report:")
print(classification_report(y_test, preds))

# Confusion Matrix
print("\nConfusion Matrix:")
print(confusion_matrix(y_test, preds))

# Save model
joblib.dump(model, 'model/ids_model.pkl')

print("\nModel saved successfully!")