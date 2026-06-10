import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
import joblib

def preprocess(df, fit=True, encoders=None, scaler=None):
    df = df.copy()

    # Drop difficulty column if it exists
    df = df.drop('difficulty', axis=1, errors='ignore')

    # Convert attack types to binary
    df['label'] = df['label'].apply(lambda x: 'normal' if str(x).strip() == 'normal' else 'attack')

    cat_cols = ['protocol_type', 'service', 'flag']

    if fit:
        # Build manual mapping dictionaries for each categorical column
        encoders = {}
        for col in cat_cols:
            unique_vals = df[col].unique().tolist()
            mapping = {val: idx for idx, val in enumerate(unique_vals)}
            encoders[col] = mapping
            df[col] = df[col].map(mapping)

        scaler = StandardScaler()
        X = df.drop('label', axis=1).astype(float)
        X_scaled = scaler.fit_transform(X)
        joblib.dump(encoders, 'model/encoders.pkl')
        joblib.dump(scaler, 'model/scaler.pkl')

    else:
        for col in cat_cols:
            mapping = encoders[col]
            # Unknown values get mapped to 0 instead of crashing
            df[col] = df[col].apply(lambda x: mapping.get(str(x).strip(), 0))

        X = df.drop('label', axis=1).astype(float)
        X_scaled = scaler.transform(X)

    y = df['label']
    return X_scaled, y, encoders, scaler