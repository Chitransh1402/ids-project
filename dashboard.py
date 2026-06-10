import streamlit as st
import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt

st.title("Cloud-Based Intrusion Detection System")
st.markdown("Upload a network log file to detect attacks in real time.")

model    = joblib.load('model/ids_model.pkl')
encoders = joblib.load('model/encoders.pkl')
scaler   = joblib.load('model/scaler.pkl')

COLS = ['duration','protocol_type','service','flag','src_bytes','dst_bytes',
        'land','wrong_fragment','urgent','hot','num_failed_logins','logged_in',
        'num_compromised','root_shell','su_attempted','num_root','num_file_creations',
        'num_shells','num_access_files','num_outbound_cmds','is_host_login',
        'is_guest_login','count','srv_count','serror_rate','srv_serror_rate',
        'rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate',
        'srv_diff_host_rate','dst_host_count','dst_host_srv_count',
        'dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate',
        'dst_host_srv_diff_host_rate','dst_host_serror_rate','dst_host_srv_serror_rate',
        'dst_host_rerror_rate','dst_host_srv_rerror_rate','label']

CAT_COLS = ['protocol_type', 'service', 'flag']

uploaded_file = st.file_uploader("Upload CSV log file", type=["csv"])

if uploaded_file:
    df = pd.read_csv(uploaded_file, names=COLS)

    # Save original text values for display before encoding
    df_display = df[['duration', 'protocol_type', 'service', 'flag', 'label']].copy()

    df = df.copy()

    # Encode categorical columns using saved mappings
    for col in CAT_COLS:
        mapping = encoders[col]
        df[col] = df[col].apply(lambda x: mapping.get(str(x).strip(), 0))

    # Drop label, convert all to float
    X = df.drop('label', axis=1)
    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0)

    X_scaled = scaler.transform(X.values)
    predictions = model.predict(X_scaled)

    df_display['prediction'] = predictions
    total   = len(predictions)
    attacks = sum(1 for p in predictions if p == 'attack')
    normal  = total - attacks

    col1, col2, col3 = st.columns(3)
    col1.metric("Total records",    total)
    col2.metric("Normal traffic",   normal)
    col3.metric("Attacks detected", attacks)

    if attacks > 0:
        st.error(f"⚠️  ALERT: {attacks} malicious connections detected!")
    else:
        st.success("✅ All traffic is normal.")

    fig, ax = plt.subplots()
    ax.pie([normal, attacks], labels=['Normal', 'Attack'],
           colors=['#4CAF50', '#F44336'], autopct='%1.1f%%')
    ax.set_title("Traffic Classification")
    st.pyplot(fig)

    # Show original readable values in table
    st.subheader("Detailed results")
    st.dataframe(df_display.head(50))