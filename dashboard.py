from dotenv import load_dotenv
load_dotenv()
import streamlit as st
import pandas as pd
import requests
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ── Page config ───────────────────────────────────────────────────────────────
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
        background: #1a1f2e; border: 1px solid #2d3748;
        border-radius: 10px; padding: 20px; text-align: center;
    }
    h1 { color: #60a5fa !important; }
</style>
""", unsafe_allow_html=True)

# ── Users & Roles ─────────────────────────────────────────────────────────────
# Roles: admin = full access | viewer = read-only (no clear log, no email test)
USERS = {
    "admin":   {"password": "ids@2024",    "role": "admin"},
    "user":    {"password": "network123",  "role": "viewer"},
    "viewer1": {"password": "view@2024",   "role": "viewer"},
    "teacher": {"password": "teacher@123", "role": "viewer"},
}

# ── Config ────────────────────────────────────────────────────────────────────
LOG_FILE     = "alerts.log"
API_URL      = os.environ.get("API_URL", "https://ids-project2-o.onrender.com")
SMTP_SENDER  = os.environ.get("SMTP_SENDER",   "chitranshs044@gmail.com")
SMTP_PASS    = os.environ.get("SMTP_PASSWORD", "")   # set in .env / Render env vars
ALERT_TO     = os.environ.get("ALERT_TO",     "yashbajhal1485@gmail.com")

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

# ── Helpers ───────────────────────────────────────────────────────────────────
def log_attack(protocol, service, flag):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(LOG_FILE, 'a') as f:
        f.write(f"[{timestamp}] ATTACK DETECTED | protocol={protocol} | service={service} | flag={flag}\n")

def send_email_alert(total, attacks, normal, filename="uploaded file"):
    if not SMTP_PASS:
        return False, "SMTP_PASSWORD not configured."
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"🚨 IDS ALERT: {attacks} Attack(s) Detected"
        msg["From"]    = SMTP_SENDER
        msg["To"]      = ALERT_TO
        timestamp      = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        html = f"""
        <html><body style="font-family:Arial,sans-serif;background:#0e1117;color:#e2e8f0;padding:20px;">
        <div style="max-width:600px;margin:auto;background:#1a1f2e;border-radius:12px;padding:24px;border:1px solid #2d3748;">
          <h2 style="color:#ef4444;">🚨 Intrusion Detection Alert</h2>
          <p style="color:#94a3b8;">Detected at: <strong>{timestamp}</strong></p>
          <p style="color:#94a3b8;">File: <strong>{filename}</strong></p>
          <hr style="border-color:#2d3748;">
          <table width="100%" style="border-collapse:collapse;margin:16px 0;">
            <tr>
              <td style="padding:12px;background:#0e1117;border-radius:8px;text-align:center;">
                <div style="font-size:28px;font-weight:bold;color:#ef4444;">{attacks}</div>
                <div style="color:#94a3b8;font-size:12px;">Attacks Detected</div>
              </td>
              <td width="10"></td>
              <td style="padding:12px;background:#0e1117;border-radius:8px;text-align:center;">
                <div style="font-size:28px;font-weight:bold;color:#22c55e;">{normal}</div>
                <div style="color:#94a3b8;font-size:12px;">Normal Traffic</div>
              </td>
              <td width="10"></td>
              <td style="padding:12px;background:#0e1117;border-radius:8px;text-align:center;">
                <div style="font-size:28px;font-weight:bold;color:#60a5fa;">{total}</div>
                <div style="color:#94a3b8;font-size:12px;">Total Records</div>
              </td>
            </tr>
          </table>
          <hr style="border-color:#2d3748;">
          <p style="color:#94a3b8;font-size:12px;">
            Sent by Cloud-Based IDS · NSL-KDD · Random Forest<br>
            Dashboard: <a href="https://ids-project-dashboard.onrender.com" style="color:#60a5fa;">ids-project-dashboard.onrender.com</a>
          </p>
        </div></body></html>"""
        msg.attach(MIMEText(html, "html"))
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(SMTP_SENDER, SMTP_PASS)
            server.sendmail(SMTP_SENDER, ALERT_TO, msg.as_string())
        return True, "Email sent!"
    except Exception as e:
        return False, str(e)

def compute_metrics(df_res):
    """Compute precision, recall, F1 from label vs prediction columns."""
    valid = df_res[df_res['prediction'].isin(['attack','normal'])].copy()
    if valid.empty:
        return None
    valid['true'] = valid['label'].apply(lambda x: 1 if str(x).strip().lower() != 'normal' else 0)
    valid['pred'] = valid['prediction'].apply(lambda x: 1 if x == 'attack' else 0)
    tp = ((valid['true']==1) & (valid['pred']==1)).sum()
    tn = ((valid['true']==0) & (valid['pred']==0)).sum()
    fp = ((valid['true']==0) & (valid['pred']==1)).sum()
    fn = ((valid['true']==1) & (valid['pred']==0)).sum()
    accuracy  = (tp+tn)/(tp+tn+fp+fn) if (tp+tn+fp+fn) > 0 else 0
    precision = tp/(tp+fp) if (tp+fp) > 0 else 0
    recall    = tp/(tp+fn) if (tp+fn) > 0 else 0
    f1        = 2*precision*recall/(precision+recall) if (precision+recall) > 0 else 0
    return {"tp":int(tp),"tn":int(tn),"fp":int(fp),"fn":int(fn),
            "accuracy":accuracy,"precision":precision,"recall":recall,"f1":f1}

# ── Login page ────────────────────────────────────────────────────────────────
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
            if username in USERS and USERS[username]["password"] == password:
                st.session_state["logged_in"] = True
                st.session_state["username"]  = username
                st.session_state["role"]      = USERS[username]["role"]
                st.rerun()
            else:
                st.error("Invalid username or password.")
        st.markdown("<br>", unsafe_allow_html=True)
        st.caption("Admin → admin / ids@2024   |   Viewer → user / network123")

# ── Main dashboard ────────────────────────────────────────────────────────────
def dashboard():
    role = st.session_state.get("role", "viewer")
    is_admin = (role == "admin")

    with st.sidebar:
        st.markdown("### 🛡️ IDS Dashboard")
        st.markdown(f"Logged in as **{st.session_state['username']}**")
        role_badge = "🔴 Admin" if is_admin else "🟢 Viewer"
        st.markdown(f"Role: {role_badge}")
        st.markdown("---")
        st.markdown("**API Status**")
        try:
            r = requests.get(f"{API_URL}/health", timeout=5)
            if r.status_code == 200:
                st.success("✅ API Online")
            else:
                st.error("❌ API Error")
        except Exception:
            st.error("❌ API Offline")
            st.caption(f"Expected at {API_URL}")
        st.markdown("---")
        if is_admin:
            st.markdown("**Email Alerts**")
            if SMTP_PASS:
                st.success("✅ Configured")
            else:
                st.warning("⚠️ SMTP_PASSWORD not set")
            if st.button("📧 Test Email"):
                ok, msg = send_email_alert(1, 1, 0, "test")
                if ok:
                    st.success("Test email sent!")
                else:
                    st.error(f"Failed: {msg}")
        st.markdown("---")
        if st.button("Sign Out"):
            st.session_state.clear()
            st.rerun()

    st.title("🛡️ Cloud-Based Intrusion Detection System")
    st.caption("NSL-KDD · Random Forest · Real-time CSV Analysis")

    tab1, tab2, tab3 = st.tabs(["📂 Analyze Traffic", "📊 Statistics & Metrics", "📋 Attack Log"])

    # ── Tab 1 ─────────────────────────────────────────────────────────────────
    with tab1:
        st.markdown("### Upload Network Log")
        st.info("Upload a CSV file with 41 network features. Use files from the `demo/` folder to test.")
        uploaded_file = st.file_uploader("Choose a CSV file", type=["csv"])

        if uploaded_file:
            df = pd.read_csv(uploaded_file, names=COLS)
            df_display = df.copy()
            filename = uploaded_file.name

            try:
                requests.get(f"{API_URL}/health", timeout=5)
            except Exception:
                st.error("❌ Flask API is not running.")
                st.stop()

            predictions = []
            st.markdown("**Processing records...**")
            progress    = st.progress(0)
            status_text = st.empty()

            for idx, (_, row) in enumerate(df.iterrows()):
                payload = row.drop('label').to_dict()
                payload = {k: float(v) if hasattr(v, 'item') else v for k, v in payload.items()}
                try:
                    response = requests.post(f"{API_URL}/predict", json=payload, timeout=5)
                    result   = response.json()
                    predictions.append(result['prediction'])
                    if result['prediction'] == 'attack':
                        log_attack(str(row['protocol_type']), str(row['service']), str(row['flag']))
                except Exception:
                    predictions.append('error')
                progress.progress((idx+1)/len(df))
                status_text.caption(f"Processed {idx+1} / {len(df)} records")

            progress.empty()
            status_text.empty()

            df_display['prediction'] = predictions
            total   = len(predictions)
            attacks = predictions.count('attack')
            normal  = predictions.count('normal')
            errors  = predictions.count('error')

            c1,c2,c3,c4 = st.columns(4)
            c1.metric("📦 Total Records",    total)
            c2.metric("✅ Normal Traffic",   normal)
            c3.metric("🚨 Attacks Detected", attacks)
            if errors: c4.metric("⚠️ Errors", errors)

            if attacks > 0:
                st.error(f"🚨 ALERT: {attacks} malicious connection(s) detected!")
                # Send email alert automatically
                if SMTP_PASS:
                    ok, msg = send_email_alert(total, attacks, normal, filename)
                    if ok:
                        st.info(f"📧 Email alert sent to {ALERT_TO}")
                    else:
                        st.warning(f"📧 Email failed: {msg}")
            else:
                st.success("✅ No attacks detected. All traffic is normal.")

            st.markdown("### Results (first 50 rows)")
            def highlight_attack(val):
                if val == 'attack': return 'background-color:#7f1d1d;color:#fca5a5;'
                if val == 'normal': return 'background-color:#14532d;color:#86efac;'
                return ''

            styled = df_display[['duration','protocol_type','service','flag','label','prediction']].head(50).reset_index(drop=True)
            st.dataframe(styled.style.map(highlight_attack, subset=['prediction']),
                         use_container_width=True, hide_index=True)

            st.session_state['last_results'] = {
                'total':total,'attacks':attacks,'normal':normal,
                'df':df_display,'filename':filename
            }

    # ── Tab 2 ─────────────────────────────────────────────────────────────────
    with tab2:
        if 'last_results' not in st.session_state:
            st.info("Upload and analyze a file in the **Analyze Traffic** tab first.")
        else:
            res = st.session_state['last_results']
            df_res = res['df']
            total,attacks,normal = res['total'],res['attacks'],res['normal']

            # ── Metrics cards ──────────────────────────────────────────────
            st.markdown("### 📈 Model Performance Metrics")
            metrics = compute_metrics(df_res)
            if metrics:
                m1,m2,m3,m4 = st.columns(4)
                m1.metric("🎯 Accuracy",  f"{metrics['accuracy']*100:.1f}%")
                m2.metric("🔍 Precision", f"{metrics['precision']*100:.1f}%")
                m3.metric("📡 Recall",    f"{metrics['recall']*100:.1f}%")
                m4.metric("⚖️ F1 Score",  f"{metrics['f1']*100:.1f}%")
                st.caption("Metrics computed by comparing the `label` column (ground truth) vs model `prediction`.")
            st.markdown("---")

            col1,col2 = st.columns(2)

            # ── Pie chart ──────────────────────────────────────────────────
            with col1:
                st.markdown("#### Traffic Classification")
                fig1,ax1 = plt.subplots(figsize=(5,4))
                fig1.patch.set_facecolor('#1a1f2e')
                ax1.set_facecolor('#1a1f2e')
                if normal > 0 or attacks > 0:
                    wedges,texts,autotexts = ax1.pie(
                        [normal,attacks], labels=['Normal','Attack'],
                        colors=['#22c55e','#ef4444'], autopct='%1.1f%%',
                        startangle=90, textprops={'color':'white'})
                    for at in autotexts: at.set_color('white')
                ax1.set_title("Normal vs Attack", color='white')
                st.pyplot(fig1); plt.close()

            # ── Confusion matrix ───────────────────────────────────────────
            with col2:
                st.markdown("#### Confusion Matrix")
                if metrics:
                    cm = np.array([[metrics['tn'], metrics['fp']],
                                   [metrics['fn'], metrics['tp']]])
                    fig_cm, ax_cm = plt.subplots(figsize=(5,4))
                    fig_cm.patch.set_facecolor('#1a1f2e')
                    ax_cm.set_facecolor('#1a1f2e')
                    im = ax_cm.imshow(cm, interpolation='nearest', cmap='RdYlGn')
                    ax_cm.set_title("Confusion Matrix", color='white')
                    ax_cm.set_xlabel("Predicted Label", color='white')
                    ax_cm.set_ylabel("True Label", color='white')
                    ax_cm.set_xticks([0,1]); ax_cm.set_yticks([0,1])
                    ax_cm.set_xticklabels(['Normal','Attack'], color='white')
                    ax_cm.set_yticklabels(['Normal','Attack'], color='white')
                    for i in range(2):
                        for j in range(2):
                            ax_cm.text(j, i, str(cm[i,j]),
                                       ha='center', va='center',
                                       color='white', fontsize=18, fontweight='bold')
                    labels = [['TN','FP'],['FN','TP']]
                    for i in range(2):
                        for j in range(2):
                            ax_cm.text(j, i+0.3, labels[i][j],
                                       ha='center', va='center',
                                       color='#94a3b8', fontsize=10)
                    plt.tight_layout()
                    st.pyplot(fig_cm); plt.close()
                else:
                    st.info("Not enough data for confusion matrix.")

            # ── Protocol bar ───────────────────────────────────────────────
            attack_rows = df_res[df_res['prediction']=='attack']
            col3,col4   = st.columns(2)

            with col3:
                st.markdown("#### Protocol Distribution (Attacks)")
                if not attack_rows.empty:
                    proto_counts = attack_rows['protocol_type'].value_counts()
                    fig2,ax2 = plt.subplots(figsize=(5,4))
                    fig2.patch.set_facecolor('#1a1f2e'); ax2.set_facecolor('#1a1f2e')
                    ax2.bar(proto_counts.index, proto_counts.values,
                            color=['#ef4444','#f97316','#eab308'][:len(proto_counts)])
                    ax2.set_xlabel("Protocol",color='white'); ax2.set_ylabel("Count",color='white')
                    ax2.tick_params(colors='white'); ax2.set_title("Attacks by Protocol",color='white')
                    for spine in ax2.spines.values(): spine.set_edgecolor('#2d3748')
                    st.pyplot(fig2); plt.close()
                else:
                    st.success("No attacks to chart.")

            with col4:
                st.markdown("#### Top 10 Targeted Services")
                if not attack_rows.empty:
                    svc_counts = attack_rows['service'].value_counts().head(10)
                    fig3,ax3 = plt.subplots(figsize=(5,4))
                    fig3.patch.set_facecolor('#1a1f2e'); ax3.set_facecolor('#1a1f2e')
                    ax3.barh(svc_counts.index[::-1], svc_counts.values[::-1], color='#ef4444')
                    ax3.tick_params(colors='white')
                    ax3.set_xlabel("Attack Count",color='white')
                    for spine in ax3.spines.values(): spine.set_edgecolor('#2d3748')
                    st.pyplot(fig3); plt.close()

    # ── Tab 3 ─────────────────────────────────────────────────────────────────
    with tab3:
        st.markdown("### Attack Log")
        col_a,col_b = st.columns([3,1])
        with col_b:
            if is_admin:
                if st.button("🗑️ Clear Log"):
                    open(LOG_FILE,'w').close()
                    st.success("Log cleared.")
                    st.rerun()
            else:
                st.caption("🔒 Admin only")

        if os.path.exists(LOG_FILE):
            with open(LOG_FILE,'r') as f:
                log_contents = f.read().strip()
            if log_contents:
                lines = log_contents.split('\n')
                st.caption(f"{len(lines)} attack(s) recorded")
                st.code(log_contents, language=None)
            else:
                st.info("No attacks logged yet.")
        else:
            st.info("No log file found yet.")

# ── Entry ─────────────────────────────────────────────────────────────────────
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False

if st.session_state["logged_in"]:
    dashboard()
else:
    login_page()
