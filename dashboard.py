import streamlit as st
import pandas as pd
import requests
import matplotlib.pyplot as plt
from datetime import datetime
import os

st.title("Cloud-Based Intrusion Detection System")
st.markdown("Upload a network log file to detect attacks in real time.")

LOG_FILE = 'alerts.log'

def log_attack(service, protocol, flag):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    line = f"[{timestamp}] ATTACK DETECTED | protocol={protocol} | service={service} | flag={flag}\n"
    with open(LOG_FILE, 'a') as f:
        f.write(line)

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

uploaded_file = st.file_uploader("Upload CSV log file", type=["csv"])

if uploaded_file:
    df = pd.read_csv(uploaded_file, names=COLS)
    df_display = df.copy()

    # Check Flask API is reachable before processing
    try:
        requests.get('http://localhost:5000/health', timeout=3)
    except Exception:
        st.error("❌ Flask API is not running. Start it with: python app.py")
        st.stop()

    predictions = []
    progress = st.progress(0)

    for idx, (_, row) in enumerate(df.iterrows()):
        payload = row.drop('label').to_dict()
        # Convert numpy types to plain Python types for JSON serialization
        payload = {k: float(v) if hasattr(v, 'item') else v for k, v in payload.items()}
        try:
            response = requests.post(
                'http://localhost:5000/predict',
                json=payload,
                timeout=5
            )
            result = response.json()
            predictions.append(result['prediction'])

            # Log attack to file
            if result['prediction'] == 'attack':
                log_attack(
                    service=str(row.get('service', 'unknown')),
                    protocol=str(row.get('protocol_type', 'unknown')),
                    flag=str(row.get('flag', 'unknown'))
                )
        except Exception:
            predictions.append('error')
        progress.progress((idx + 1) / len(df))

    progress.empty()

    df_display['prediction'] = predictions
    total   = len(predictions)
    attacks = sum(1 for p in predictions if p == 'attack')
    normal  = sum(1 for p in predictions if p == 'normal')
    errors  = sum(1 for p in predictions if p == 'error')

    col1, col2, col3 = st.columns(3)
    col1.metric("Total records",    total)
    col2.metric("Normal traffic",   normal)
    col3.metric("Attacks detected", attacks)

    if errors > 0:
        st.warning(f"⚠️ {errors} rows could not be processed by the API.")

    if attacks > 0:
        st.error(f"⚠️  ALERT: {attacks} malicious connections detected!")
    elif normal > 0:
        st.success("✅ All traffic is normal.")

    # Only show pie chart if we have valid predictions
    if normal > 0 or attacks > 0:
        fig, ax = plt.subplots()
        ax.pie([normal, attacks], labels=['Normal', 'Attack'],
               colors=['#4CAF50', '#F44336'], autopct='%1.1f%%')
        ax.set_title("Traffic Classification")
        st.pyplot(fig)

    st.subheader("Detailed results")
    st.dataframe(df_display[['duration','protocol_type','service','flag','label','prediction']].head(50))

    # Show alert log if it exists
    if os.path.exists(LOG_FILE):
        st.subheader("Attack log")
        with open(LOG_FILE, 'r') as f:
            log_contents = f.read()
        if log_contents:
            st.code(log_contents)
        else:
            st.write("No attacks logged yet.")