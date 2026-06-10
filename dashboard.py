import streamlit as st
import pandas as pd
import requests
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from datetime import datetime
import os

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="IDS Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .main { background-color: #0e1117; }
    .metric-card {
        background: #1a1f2e;
        border: 1px solid #2d3748;
        border-radius: 10px;
        padding: 20px;
        text-align: center;
    }
    .attack-badge {
        background: #7f1d1d;
        color: #fca5a5;
        padding: 4px 10px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: bold;
    }
    .normal-badge {
        background: #14532d;
        color: #86efac;
        padding: 4px 10px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: bold;
    }
    h1 { color: #60a5fa !important; }
</style>
""", unsafe_allow_html=True)

# ── Credentials ───────────────────────────────────────────────────────────────
USERS = {
    "admin": "ids@2024",
    "user":  "network123",
}

LOG_FILE = "alerts.log"
API_URL  = os.environ.get("API_URL", "https://ids-project2-o.onrender.com")

COLS = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes',
    'land','wrong_fragment','urgent','hot','num_failed_logins','logged_in',
    'num_compromised','root_shell','su_attempted','num_root','num_file_creations',
    'num_shells','num_access_files','num_outbound_cmds','is_host_login',
    'is_guest_login','count','srv_count','serror_rate','srv_serror_rate',
    'rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate',
    'srv_diff_host_rate','dst_host_count','dst_host_srv_count',
    'dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate','dst_host_serror_rate','dst_host_srv_serror_rate',
    'dst_host_rerror_rate','dst_host_srv_rerror_rate','label'
]

# ── Logger ────────────────────────────────────────────────────────────────────
def log_attack(protocol, service, flag):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(LOG_FILE, 'a') as f:
        f.write(f"[{timestamp}] ATTACK DETECTED | protocol={protocol} | service={service} | flag={flag}\n")

# ── Login ─────────────────────────────────────────────────────────────────────
def login_page():
    col1, col2, col3 = st.columns([1, 1.2, 1])
    with col2:
        st.markdown("<br><br>", unsafe_allow_html=True)
        st.markdown("## 🛡️ IDS — Sign In")
        st.markdown("Cloud-Based Intelligent Intrusion Detection System")
        st.markdown("---")
        username = st.text_input("Username", placeholder="admin")
        password = st.text_input("Password", type="password", placeholder="••••••••")
        if st.button("Sign In", use_container_width=True, type="primary"):
            if username in USERS and USERS[username] == password:
                st.session_state["logged_in"] = True
                st.session_state["username"] = username
                st.rerun()
            else:
                st.error("Invalid username or password.")
        st.markdown("<br>", unsafe_allow_html=True)
        st.caption("Default credentials → admin / ids@2024")

# ── Main dashboard ────────────────────────────────────────────────────────────
def dashboard():
    # Sidebar
    with st.sidebar:
        st.markdown(f"### 🛡️ IDS Dashboard")
        st.markdown(f"Logged in as **{st.session_state['username']}**")
        st.markdown("---")
        st.markdown("**API Status**")
        try:
            r = requests.get(f"{API_URL}/health", timeout=3)
            if r.status_code == 200:
                st.success("✅ API Online")
            else:
                st.error("❌ API Error")
        except Exception:
            st.error("❌ API Offline")
            st.caption(f"Expected at {API_URL}\nRun: `python app.py`")
        st.markdown("---")
        if st.button("Sign Out"):
            st.session_state.clear()
            st.rerun()

    st.title("🛡️ Cloud-Based Intrusion Detection System")
    st.caption("NSL-KDD · Random Forest · Real-time CSV Analysis")

    tab1, tab2, tab3 = st.tabs(["📂 Analyze Traffic", "📊 Statistics", "📋 Attack Log"])

    # ── Tab 1: Analyze ────────────────────────────────────────────────────────
    with tab1:
        st.markdown("### Upload Network Log")
        st.info("Upload a CSV file with 41 network features. Use the demo files in the `demo/` folder to test.")
        uploaded_file = st.file_uploader("Choose a CSV file", type=["csv"])

        if uploaded_file:
            df = pd.read_csv(uploaded_file, names=COLS)
            df_display = df.copy()

            try:
                requests.get(f"{API_URL}/health", timeout=3)
            except Exception:
                st.error("❌ Flask API is not running. Start it with: `python app.py`")
                st.stop()

            predictions = []
            st.markdown("**Processing records...**")
            progress = st.progress(0)
            status_text = st.empty()

            for idx, (_, row) in enumerate(df.iterrows()):
                payload = row.drop('label').to_dict()
                payload = {k: float(v) if hasattr(v, 'item') else v for k, v in payload.items()}
                try:
                    response = requests.post(f"{API_URL}/predict", json=payload, timeout=5)
                    result = response.json()
                    predictions.append(result['prediction'])
                    if result['prediction'] == 'attack':
                        log_attack(
                            protocol=str(row['protocol_type']),
                            service=str(row['service']),
                            flag=str(row['flag'])
                        )
                except Exception:
                    predictions.append('error')

                pct = (idx + 1) / len(df)
                progress.progress(pct)
                status_text.caption(f"Processed {idx+1} / {len(df)} records")

            progress.empty()
            status_text.empty()

            df_display['prediction'] = predictions
            total   = len(predictions)
            attacks = predictions.count('attack')
            normal  = predictions.count('normal')
            errors  = predictions.count('error')

            # Metrics row
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("📦 Total Records",    total)
            c2.metric("✅ Normal Traffic",   normal)
            c3.metric("🚨 Attacks Detected", attacks)
            if errors:
                c4.metric("⚠️ Errors", errors)

            # Alert banner
            if attacks > 0:
                st.error(f"🚨 ALERT: {attacks} malicious connection(s) detected in this log file!")
            else:
                st.success("✅ No attacks detected. All traffic is normal.")

            # Results table
            st.markdown("### Results (first 50 rows)")
            def highlight_attack(val):
                if val == 'attack':
                    return 'background-color: #7f1d1d; color: #fca5a5;'
                elif val == 'normal':
                    return 'background-color: #14532d; color: #86efac;'
                return ''

            styled = df_display[['duration','protocol_type','service','flag','label','prediction']].head(50).reset_index(drop=True)
            st.dataframe(
                styled.style.map(highlight_attack, subset=['prediction']),
                use_container_width=True,
                hide_index=True
            )

            # Store for statistics tab
            st.session_state['last_results'] = {
                'total': total, 'attacks': attacks, 'normal': normal,
                'df': df_display
            }

    # ── Tab 2: Statistics ─────────────────────────────────────────────────────
    with tab2:
        if 'last_results' not in st.session_state:
            st.info("Upload and analyze a file in the **Analyze Traffic** tab first.")
        else:
            res = st.session_state['last_results']
            df_res = res['df']
            total, attacks, normal = res['total'], res['attacks'], res['normal']

            col1, col2 = st.columns(2)

            with col1:
                st.markdown("#### Traffic Classification")
                fig1, ax1 = plt.subplots(figsize=(5, 4))
                fig1.patch.set_facecolor('#1a1f2e')
                ax1.set_facecolor('#1a1f2e')
                if normal > 0 or attacks > 0:
                    wedges, texts, autotexts = ax1.pie(
                        [normal, attacks],
                        labels=['Normal', 'Attack'],
                        colors=['#22c55e', '#ef4444'],
                        autopct='%1.1f%%',
                        startangle=90,
                        textprops={'color': 'white'}
                    )
                    for at in autotexts:
                        at.set_color('white')
                ax1.set_title("Normal vs Attack", color='white')
                st.pyplot(fig1)
                plt.close()

            with col2:
                st.markdown("#### Protocol Distribution (Attacks)")
                attack_rows = df_res[df_res['prediction'] == 'attack']
                if not attack_rows.empty:
                    proto_counts = attack_rows['protocol_type'].value_counts()
                    fig2, ax2 = plt.subplots(figsize=(5, 4))
                    fig2.patch.set_facecolor('#1a1f2e')
                    ax2.set_facecolor('#1a1f2e')
                    bars = ax2.bar(proto_counts.index, proto_counts.values,
                                   color=['#ef4444', '#f97316', '#eab308'][:len(proto_counts)])
                    ax2.set_xlabel("Protocol", color='white')
                    ax2.set_ylabel("Count", color='white')
                    ax2.tick_params(colors='white')
                    ax2.set_title("Attacks by Protocol", color='white')
                    for spine in ax2.spines.values():
                        spine.set_edgecolor('#2d3748')
                    st.pyplot(fig2)
                    plt.close()
                else:
                    st.success("No attacks to chart.")

            # Top attacked services
            if not attack_rows.empty:
                st.markdown("#### Top 10 Targeted Services")
                svc_counts = attack_rows['service'].value_counts().head(10)
                fig3, ax3 = plt.subplots(figsize=(10, 3))
                fig3.patch.set_facecolor('#1a1f2e')
                ax3.set_facecolor('#1a1f2e')
                ax3.barh(svc_counts.index[::-1], svc_counts.values[::-1], color='#ef4444')
                ax3.tick_params(colors='white')
                ax3.set_xlabel("Attack Count", color='white')
                for spine in ax3.spines.values():
                    spine.set_edgecolor('#2d3748')
                st.pyplot(fig3)
                plt.close()

    # ── Tab 3: Attack Log ─────────────────────────────────────────────────────
    with tab3:
        st.markdown("### Attack Log")
        col_a, col_b = st.columns([3, 1])
        with col_b:
            if st.button("🗑️ Clear Log"):
                open(LOG_FILE, 'w').close()
                st.success("Log cleared.")
                st.rerun()

        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r') as f:
                log_contents = f.read().strip()
            if log_contents:
                lines = log_contents.split('\n')
                st.caption(f"{len(lines)} attack(s) recorded")
                st.code(log_contents, language=None)
            else:
                st.info("No attacks logged yet.")
        else:
            st.info("No log file found yet.")

# ── Entry point ───────────────────────────────────────────────────────────────
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False

if st.session_state["logged_in"]:
    dashboard()
else:
    login_page()