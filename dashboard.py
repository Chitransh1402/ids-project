import streamlit as st
import pandas as pd
import requests
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime
import os
import joblib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
load_dotenv()

st.set_page_config(page_title="SCCA-IDS Dashboard", page_icon="🛡️",
                   layout="wide", initial_sidebar_state="expanded")

st.markdown("""<style>
    .main { background-color: #0e1117; }
    h1 { color: #60a5fa !important; }
</style>""", unsafe_allow_html=True)

USERS = {
    "admin":   {"password": "ids@2024",    "role": "admin"},
    "user":    {"password": "network123",  "role": "viewer"},
    "viewer1": {"password": "view@2024",   "role": "viewer"},
    "teacher": {"password": "teacher@123", "role": "viewer"},
}

LOG_FILE    = "alerts.log"
API_URL     = os.environ.get("API_URL",       "https://ids-project2-o.onrender.com")
SMTP_SENDER = os.environ.get("SMTP_SENDER",   "chitranshs044@gmail.com")
SMTP_PASS   = os.environ.get("SMTP_PASSWORD", "")
ALERT_TO    = os.environ.get("ALERT_TO",      "yashbajhal1485@gmail.com")
GROQ_KEY    = os.environ.get("GROQ_API_KEY",  "")

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

def log_attack(protocol, service, flag, tier=""):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(LOG_FILE, 'a') as f:
        f.write(f"[{timestamp}] ATTACK DETECTED | protocol={protocol} | service={service} | flag={flag} | tier={tier}\n")

def send_email_alert(total, attacks, normal, filename="uploaded file"):
    if not SMTP_PASS: return False, "SMTP_PASSWORD not configured."
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"🚨 IDS ALERT: {attacks} Attack(s) Detected"
        msg["From"] = SMTP_SENDER; msg["To"] = ALERT_TO
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        html = f"""<html><body style="font-family:Arial;background:#0e1117;color:#e2e8f0;padding:20px;">
        <div style="max-width:600px;margin:auto;background:#1a1f2e;border-radius:12px;padding:24px;">
        <h2 style="color:#ef4444;">🚨 SCCA-IDS Intrusion Alert</h2>
        <p>At {timestamp} — File: {filename}</p>
        <p>Attacks: <strong style="color:#ef4444">{attacks}</strong> | Normal: <strong style="color:#22c55e">{normal}</strong> | Total: {total}</p>
        <a href="https://ids-project-dashboard.onrender.com" style="color:#60a5fa">Open Dashboard</a>
        </div></body></html>"""
        msg.attach(MIMEText(html, "html"))
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
            s.login(SMTP_SENDER, SMTP_PASS); s.sendmail(SMTP_SENDER, ALERT_TO, msg.as_string())
        return True, "Email sent!"
    except Exception as e:
        return False, str(e)

def compute_metrics(df_res):
    valid = df_res[df_res['prediction'].isin(['attack','normal'])].copy()
    if valid.empty: return None
    valid['true'] = valid['label'].apply(lambda x: 1 if str(x).strip().lower() != 'normal' else 0)
    valid['pred'] = valid['prediction'].apply(lambda x: 1 if x == 'attack' else 0)
    tp = ((valid['true']==1)&(valid['pred']==1)).sum()
    tn = ((valid['true']==0)&(valid['pred']==0)).sum()
    fp = ((valid['true']==0)&(valid['pred']==1)).sum()
    fn = ((valid['true']==1)&(valid['pred']==0)).sum()
    acc = (tp+tn)/(tp+tn+fp+fn) if (tp+tn+fp+fn)>0 else 0
    pre = tp/(tp+fp) if (tp+fp)>0 else 0
    rec = tp/(tp+fn) if (tp+fn)>0 else 0
    f1  = 2*pre*rec/(pre+rec) if (pre+rec)>0 else 0
    return {"tp":int(tp),"tn":int(tn),"fp":int(fp),"fn":int(fn),
            "accuracy":acc,"precision":pre,"recall":rec,"f1":f1}

def login_page():
    col1, col2, col3 = st.columns([1, 1.2, 1])
    with col2:
        st.markdown("<br><br>", unsafe_allow_html=True)
        st.markdown("## 🛡️ SCCA-IDS — Sign In")
        st.markdown("Confidence-Calibrated Intrusion Detection System")
        st.markdown("---")
        username = st.text_input("Username", placeholder="admin")
        password = st.text_input("Password", type="password", placeholder="••••••••")
        if st.button("Sign In", use_container_width=True, type="primary"):
            if username in USERS and USERS[username]["password"] == password:
                st.session_state.update({"logged_in":True,"username":username,
                                         "role":USERS[username]["role"],"chat_history":[]})
                st.rerun()
            else:
                st.error("Invalid username or password.")
        st.caption("Admin → admin / ids@2024   |   Viewer → user / network123")

def dashboard():
    role     = st.session_state.get("role", "viewer")
    is_admin = (role == "admin")

    with st.sidebar:
        st.markdown("### 🛡️ SCCA-IDS")
        st.markdown(f"**{st.session_state['username']}** | {'🔴 Admin' if is_admin else '🟢 Viewer'}")
        st.markdown("---")
        try:
            r = requests.get(f"{API_URL}/health", timeout=5)
            h = r.json()
            st.success("✅ API Online")
            if h.get("scca_available"):
                st.success("✅ Calibrated Model")
            else:
                st.warning("⚠️ Run calibration.py")
        except:
            st.error("❌ API Offline")
        st.markdown("---")
        st.markdown("**🤖 AI (RAG)**")
        st.success("✅ Groq") if GROQ_KEY else st.warning("⚠️ No Groq key")
        if is_admin:
            st.markdown("**📧 Email**")
            st.success("✅ Configured") if SMTP_PASS else st.warning("⚠️ Not set")
            if st.button("📧 Test"):
                ok,msg = send_email_alert(1,1,0,"test")
                st.success("Sent!") if ok else st.error(msg)
        st.markdown("---")
        if st.button("Sign Out"):
            st.session_state.clear(); st.rerun()

    st.title("🛡️ SCCA-IDS: Confidence-Calibrated Intrusion Detection")
    st.caption("NSL-KDD · Random Forest · Isotonic Calibration · SHAP Consistency · Federated Learning · RAG AI")

    (tab1, tab2, tab3, tab_scca,
     tab4, tab5, tab6, tab7) = st.tabs([
        "📂 Analyze Traffic",
        "📊 Statistics & Metrics",
        "📋 Attack Log",
        "🎯 SCCA-IDS",
        "🤝 Federated Learning",
        "🔍 AI Threat Explainer",
        "💬 AI Chatbot",
        "📝 AI Report",
    ])

    # ── Tab 1: Analyze ────────────────────────────────────────────────────────
    with tab1:
        st.markdown("### Upload Network Log")
        st.info("Upload a CSV with 41 network features. Use files from `demo/` folder.")
        uploaded_file = st.file_uploader("Choose a CSV file", type=["csv"])
        if uploaded_file:
            df = pd.read_csv(uploaded_file, names=COLS)
            df_display = df.copy()
            filename = uploaded_file.name
            try: requests.get(f"{API_URL}/health", timeout=5)
            except: st.error("❌ Flask API offline."); st.stop()
            predictions = []
            progress = st.progress(0); status_text = st.empty()
            for idx, (_, row) in enumerate(df.iterrows()):
                payload = row.drop('label').to_dict()
                payload = {k: float(v) if hasattr(v,'item') else v for k,v in payload.items()}
                try:
                    res = requests.post(f"{API_URL}/predict", json=payload, timeout=5).json()
                    predictions.append(res['prediction'])
                    if res['prediction']=='attack':
                        log_attack(str(row['protocol_type']),str(row['service']),str(row['flag']))
                except: predictions.append('error')
                progress.progress((idx+1)/len(df))
                status_text.caption(f"Processed {idx+1} / {len(df)} records")
            progress.empty(); status_text.empty()
            df_display['prediction'] = predictions
            total=len(predictions); attacks=predictions.count('attack')
            normal=predictions.count('normal'); errors=predictions.count('error')
            c1,c2,c3,c4 = st.columns(4)
            c1.metric("📦 Total",total); c2.metric("✅ Normal",normal)
            c3.metric("🚨 Attacks",attacks)
            if errors: c4.metric("⚠️ Errors",errors)
            if attacks>0:
                st.error(f"🚨 {attacks} malicious connection(s) detected!")
                if SMTP_PASS:
                    ok,msg = send_email_alert(total,attacks,normal,filename)
                    st.info(f"📧 Email sent") if ok else st.warning(f"📧 Failed: {msg}")
            else:
                st.success("✅ No attacks detected.")
            st.markdown("### Results (first 50 rows)")
            def hl(val):
                if val=='attack': return 'background-color:#7f1d1d;color:#fca5a5;'
                if val=='normal': return 'background-color:#14532d;color:#86efac;'
                return ''
            # Only show basic columns in Analyze tab
            basic_cols = ['duration','protocol_type','service','flag','label','prediction']
            styled = df_display[basic_cols].head(50).reset_index(drop=True)
            st.dataframe(styled.style.map(hl,subset=['prediction']),
                        use_container_width=True,hide_index=True)
            st.session_state['last_results'] = {'total':total,'attacks':attacks,'normal':normal,'df':df_display,'filename':filename}

    # ── Tab 2: Statistics ─────────────────────────────────────────────────────
    with tab2:
        if 'last_results' not in st.session_state:
            st.info("Upload and analyze a file in **Analyze Traffic** tab first.")
        else:
            res=st.session_state['last_results']; df_res=res['df']
            total,attacks,normal=res['total'],res['attacks'],res['normal']
            st.markdown("### 📈 Model Performance Metrics")
            metrics=compute_metrics(df_res)
            if metrics:
                m1,m2,m3,m4=st.columns(4)
                m1.metric("🎯 Accuracy",f"{metrics['accuracy']*100:.1f}%")
                m2.metric("🔍 Precision",f"{metrics['precision']*100:.1f}%")
                m3.metric("📡 Recall",f"{metrics['recall']*100:.1f}%")
                m4.metric("⚖️ F1",f"{metrics['f1']*100:.1f}%")
            st.markdown("---")
            col1,col2=st.columns(2)
            with col1:
                st.markdown("#### Traffic Classification")
                fig1,ax1=plt.subplots(figsize=(5,4))
                fig1.patch.set_facecolor('#1a1f2e'); ax1.set_facecolor('#1a1f2e')
                if normal>0 or attacks>0:
                    _,_,at=ax1.pie([normal,attacks],labels=['Normal','Attack'],
                        colors=['#22c55e','#ef4444'],autopct='%1.1f%%',
                        startangle=90,textprops={'color':'white'})
                    for a in at: a.set_color('white')
                ax1.set_title("Normal vs Attack",color='white')
                st.pyplot(fig1); plt.close()
            with col2:
                st.markdown("#### Confusion Matrix")
                if metrics:
                    cm=np.array([[metrics['tn'],metrics['fp']],[metrics['fn'],metrics['tp']]])
                    fig_cm,ax_cm=plt.subplots(figsize=(5,4))
                    fig_cm.patch.set_facecolor('#1a1f2e'); ax_cm.set_facecolor('#1a1f2e')
                    ax_cm.imshow(cm,interpolation='nearest',cmap='RdYlGn')
                    ax_cm.set_title("Confusion Matrix",color='white')
                    ax_cm.set_xlabel("Predicted",color='white'); ax_cm.set_ylabel("Actual",color='white')
                    ax_cm.set_xticks([0,1]); ax_cm.set_yticks([0,1])
                    ax_cm.set_xticklabels(['Normal','Attack'],color='white')
                    ax_cm.set_yticklabels(['Normal','Attack'],color='white')
                    lbl=[['TN','FP'],['FN','TP']]
                    for i in range(2):
                        for j in range(2):
                            ax_cm.text(j,i,str(cm[i,j]),ha='center',va='center',color='white',fontsize=18,fontweight='bold')
                            ax_cm.text(j,i+0.3,lbl[i][j],ha='center',va='center',color='#94a3b8',fontsize=10)
                    plt.tight_layout(); st.pyplot(fig_cm); plt.close()
            attack_rows=df_res[df_res['prediction']=='attack']
            col3,col4=st.columns(2)
            with col3:
                st.markdown("#### Protocol Distribution")
                if not attack_rows.empty:
                    pc=attack_rows['protocol_type'].value_counts()
                    fig2,ax2=plt.subplots(figsize=(5,4))
                    fig2.patch.set_facecolor('#1a1f2e'); ax2.set_facecolor('#1a1f2e')
                    ax2.bar(pc.index,pc.values,color=['#ef4444','#f97316','#eab308'][:len(pc)])
                    ax2.set_xlabel("Protocol",color='white'); ax2.tick_params(colors='white')
                    st.pyplot(fig2); plt.close()
                else: st.success("No attacks.")
            with col4:
                st.markdown("#### Top 10 Services")
                if not attack_rows.empty:
                    sc=attack_rows['service'].value_counts().head(10)
                    fig3,ax3=plt.subplots(figsize=(5,4))
                    fig3.patch.set_facecolor('#1a1f2e'); ax3.set_facecolor('#1a1f2e')
                    ax3.barh(sc.index[::-1],sc.values[::-1],color='#ef4444')
                    ax3.tick_params(colors='white')
                    st.pyplot(fig3); plt.close()

    # ── Tab 3: Attack Log ─────────────────────────────────────────────────────
    with tab3:
        st.markdown("### Attack Log")
        ca,cb=st.columns([3,1])
        with cb:
            if is_admin:
                if st.button("🗑️ Clear"): open(LOG_FILE,'w').close(); st.rerun()
            else: st.caption("🔒 Admin only")
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE,'r') as f: lc=f.read().strip()
            if lc:
                st.caption(f"{len(lc.split(chr(10)))} attack(s) recorded")
                st.code(lc,language=None)
            else: st.info("No attacks logged yet.")
        else: st.info("No log file found.")

    # ── SCCA-IDS Tab ──────────────────────────────────────────────────────────
    with tab_scca:
        st.markdown("### 🎯 SCCA-IDS: Confidence-Calibrated Alert Analysis")
        st.info(
            "**SCCA-IDS** combines **isotonic probability calibration** with "
            "**SHAP consistency scoring** to produce per-alert confidence tiers. "
            "HIGH tier = auto-alert. LOW tier = suppress (likely false positive)."
        )

        # ── Calibration step ──────────────────────────────────────────────────
        st.markdown("---")
        st.markdown("#### ⚙️ Step 1 — Run Calibration (one-time setup)")
        col_c1, col_c2 = st.columns([1, 3])
        with col_c1:
            run_cal = st.button("⚙️ Run Calibration", type="primary",
                                disabled=not is_admin)
        with col_c2:
            if not is_admin:
                st.warning("🔒 Admin only — login as admin to run calibration.")

        cal_results = None
        try:
            r = requests.get(f"{API_URL}/calibration_results", timeout=5)
            if r.status_code == 200:
                cal_results = r.json()
        except Exception:
            pass

        if run_cal and is_admin:
            with st.spinner("Running isotonic calibration on NSL-KDD (~30 seconds)..."):
                try:
                    import calibration as cal_module
                    cal_results = cal_module.run_calibration_pipeline()
                    st.success("✅ Calibration complete! Restart Flask API (`python app.py`) to load the calibrated model.")
                except Exception as e:
                    st.error(f"Calibration error: {e}")

        if cal_results:
            st.markdown("#### 📐 Calibration Metrics")
            m1,m2,m3,m4 = st.columns(4)
            m1.metric("ECE Before",   f"{cal_results.get('ece_before','—')}",
                      help="Expected Calibration Error — lower is better")
            m2.metric("ECE After",    f"{cal_results.get('ece_after','—')}",
                      delta=f"-{cal_results.get('ece_reduction','—')}%",
                      delta_color="inverse")
            m3.metric("Brier Before", f"{cal_results.get('brier_before','—')}")
            m4.metric("Brier After",  f"{cal_results.get('brier_after','—')}",
                      delta=f"-{cal_results.get('brier_reduction','—')}%",
                      delta_color="inverse")

            if os.path.exists('model/calibration_curve.png'):
                st.markdown("#### 📈 Reliability Diagram")
                from PIL import Image
                img = Image.open('model/calibration_curve.png')
                st.image(img, use_column_width=True,
                         caption="Diagonal line = perfect calibration. "
                                 "After calibration should be closer to diagonal.")
        else:
            st.warning("⚠️ No calibration results yet. Click **Run Calibration** above.")

        # ── SCCA Analysis step ────────────────────────────────────────────────
        st.markdown("---")
        st.markdown("#### 📂 Step 2 — SCCA-IDS Traffic Analysis")
        scca_file = st.file_uploader(
            "Upload CSV for SCCA-IDS analysis",
            type=["csv"], key="scca_uploader"
        )

        if scca_file:
            df_scca = pd.read_csv(scca_file, names=COLS)
            try:
                r = requests.get(f"{API_URL}/health", timeout=5)
                scca_available = r.json().get("scca_available", False)
            except:
                st.error("❌ API offline."); st.stop()

            if not scca_available:
                st.warning("⚠️ Calibrated model not loaded in API. "
                           "Run calibration first, then restart `python app.py`.")

            results_list = []
            prog = st.progress(0); stat = st.empty()
            for idx, (_, row) in enumerate(df_scca.iterrows()):
                payload = row.drop('label').to_dict()
                payload = {k: float(v) if hasattr(v,'item') else v
                           for k,v in payload.items()}
                try:
                    res = requests.post(f"{API_URL}/predict_scca",
                                        json=payload, timeout=10).json()
                    if 'error' in res:
                        results_list.append({
                            'prediction':'error','tier':'ERROR',
                            'confidence_index':None,'calibrated_prob':None,
                            'attack_probability':None,
                            'shap_consistency':None,'top_feature':res['error'][:30],
                            'label':str(row['label']),
                            'protocol_type':str(row['protocol_type']),
                            'service':str(row['service']),
                            'flag':str(row['flag']),
                        })
                    else:
                        res.update({
                            'label':        str(row['label']),
                            'protocol_type':str(row['protocol_type']),
                            'service':      str(row['service']),
                            'flag':         str(row['flag']),
                        })
                        if res.get('prediction') == 'attack':
                            log_attack(str(row['protocol_type']),
                                       str(row['service']),
                                       str(row['flag']),
                                       tier=res.get('tier',''))
                        results_list.append(res)
                except Exception as ex:
                    results_list.append({
                        'prediction':'error','tier':'LOW',
                        'confidence_index':0,'calibrated_prob':0,
                        'shap_consistency':0,'top_feature':'error',
                        'label':str(row['label']),
                        'protocol_type':str(row['protocol_type']),
                        'service':str(row['service']),
                        'flag':str(row['flag']),
                    })
                prog.progress((idx+1)/len(df_scca))
                stat.caption(f"Processed {idx+1} / {len(df_scca)} records")

            prog.empty(); stat.empty()
            df_r = pd.DataFrame(results_list)

            total  = len(df_r)
            attacks= (df_r['prediction']=='attack').sum()
            normal = (df_r['prediction']=='normal').sum()
            high   = (df_r['tier']=='HIGH').sum()
            medium = (df_r['tier']=='MEDIUM').sum()
            low_t  = (df_r['tier']=='LOW').sum()

            c1,c2,c3,c4,c5,c6 = st.columns(6)
            c1.metric("Total",   total)
            c2.metric("Attacks", attacks)
            c3.metric("Normal",  normal)
            c4.metric("🔴 HIGH",   high)
            c5.metric("🟡 MED",    medium)
            c6.metric("⚪ LOW",    low_t)

            if high > 0:
                st.error(f"🚨 {high} HIGH-confidence attack(s) — immediate action required!")
            if medium > 0:
                st.warning(f"⚠️ {medium} MEDIUM-confidence alert(s) — review recommended.")
            if attacks == 0:
                st.success("✅ No attacks detected.")

            # Results table
            st.markdown("#### 📋 SCCA-IDS Results (first 50 rows)")
            show_cols = [c for c in [
                'prediction','calibrated_prob','shap_consistency',
                'confidence_index','tier','top_feature',
                'protocol_type','service','flag','label'
            ] if c in df_r.columns]
            df_show = df_r[show_cols].head(50).reset_index(drop=True)

            def hl_tier(val):
                if val=='HIGH':   return 'background-color:#7f1d1d;color:#fca5a5;font-weight:bold'
                if val=='MEDIUM': return 'background-color:#78350f;color:#fde68a;font-weight:bold'
                if val=='LOW':    return 'background-color:#1e293b;color:#94a3b8'
                return ''
            def hl_pred(val):
                if val=='attack': return 'background-color:#7f1d1d;color:#fca5a5'
                if val=='normal': return 'background-color:#14532d;color:#86efac'
                return ''

            sty = df_show.style
            if 'tier' in df_show.columns:
                sty = sty.map(hl_tier, subset=['tier'])
            if 'prediction' in df_show.columns:
                sty = sty.map(hl_pred, subset=['prediction'])
            st.dataframe(sty, use_container_width=True, hide_index=True)

            # Charts
            st.markdown("---")
            st.markdown("#### 📊 SCCA-IDS Analytics")
            ch1, ch2, ch3 = st.columns(3)

            with ch1:
                st.markdown("**Alert Tier Distribution**")
                fig,ax = plt.subplots(figsize=(4,3.5))
                fig.patch.set_facecolor('#1a1f2e'); ax.set_facecolor('#1a1f2e')
                bars = ax.bar(['HIGH','MEDIUM','LOW'],[high,medium,low_t],
                              color=['#EF4444','#F59E0B','#94A3B8'],width=0.5)
                ax.set_ylabel("Count",color="white"); ax.tick_params(colors="white")
                ax.set_title("Alert Tiers",color="white")
                for spine in ax.spines.values(): spine.set_edgecolor("#2d3748")
                for bar,val in zip(bars,[high,medium,low_t]):
                    ax.text(bar.get_x()+bar.get_width()/2,
                            bar.get_height()+0.1,str(val),
                            ha="center",color="white",fontweight="bold")
                st.pyplot(fig); plt.close()

            with ch2:
                st.markdown("**Confidence Index Distribution**")
                fig,ax = plt.subplots(figsize=(4,3.5))
                fig.patch.set_facecolor('#1a1f2e'); ax.set_facecolor('#1a1f2e')
                ci_vals = df_r['confidence_index'].dropna()
                ax.hist(ci_vals, bins=20, color='#60A5FA',
                        edgecolor='#2d3748', alpha=0.85)
                ax.axvline(70, color='#EF4444', lw=2,
                           linestyle='--', label='HIGH (70)')
                ax.axvline(40, color='#F59E0B', lw=2,
                           linestyle='--', label='MED (40)')
                ax.set_xlabel("CI (0–100)",color="white")
                ax.set_ylabel("Count",color="white"); ax.tick_params(colors="white")
                ax.set_title("CI Distribution",color="white")
                ax.legend(fontsize=8,facecolor='#1a1f2e',labelcolor='white')
                for spine in ax.spines.values(): spine.set_edgecolor("#2d3748")
                st.pyplot(fig); plt.close()

            with ch3:
                st.markdown("**SHAP Consistency Distribution**")
                fig,ax = plt.subplots(figsize=(4,3.5))
                fig.patch.set_facecolor('#1a1f2e'); ax.set_facecolor('#1a1f2e')
                sc_vals = df_r['shap_consistency'].dropna()
                ax.hist(sc_vals, bins=[0,0.34,0.67,1.01],
                        color='#22C55E', edgecolor='#2d3748', alpha=0.85)
                ax.set_xlabel("Consistency (0–1)",color="white")
                ax.set_ylabel("Count",color="white"); ax.tick_params(colors="white")
                ax.set_title("SHAP Consistency",color="white")
                for spine in ax.spines.values(): spine.set_edgecolor("#2d3748")
                st.pyplot(fig); plt.close()

            # Tier-level precision
            if 'label' in df_r.columns:
                st.markdown("---")
                st.markdown("#### 🎯 Tier-Level Precision (Key Experimental Result)")
                st.caption("HIGH tier should have highest precision. "
                           "LOW tier should contain most false positives. "
                           "This is the core ablation evidence for the paper.")

                def tier_prec(tier_name):
                    sub = df_r[df_r['tier']==tier_name]
                    if len(sub)==0: return 0,0,0
                    tp = sub[sub['label'].str.strip().str.lower()!='normal'].shape[0]
                    prec = tp/len(sub) if len(sub)>0 else 0
                    return len(sub), tp, round(prec*100,1)

                t1,t2,t3 = st.columns(3)
                for col,tier,color in zip(
                        [t1,t2,t3],
                        ['HIGH','MEDIUM','LOW'],
                        ['#EF4444','#F59E0B','#94A3B8']):
                    n,tp,prec = tier_prec(tier)
                    with col:
                        st.markdown(
                            f"""<div style="background:#1a1f2e;border:2px solid {color};
                            border-radius:10px;padding:16px;text-align:center;">
                            <div style="color:{color};font-size:20px;font-weight:bold">{tier}</div>
                            <div style="color:#e2e8f0;font-size:28px;font-weight:bold">{prec}%</div>
                            <div style="color:#94a3b8;font-size:13px">Precision</div>
                            <div style="color:#94a3b8;font-size:12px">{n} alerts · {tp} true attacks</div>
                            </div>""", unsafe_allow_html=True)

                overall_prec = round(attacks/total*100,1) if total>0 else 0
                st.info(f"📊 **Overall precision (no tiering):** {overall_prec}% across all {total} records. "
                        f"Compare to HIGH-tier precision above — the difference is your paper's key result.")
                st.success("💡 **Viva/Paper insight:** If HIGH precision > overall precision and "
                           "LOW tier contains most false positives → SCCA-IDS is working correctly.")

            st.session_state['scca_results'] = {
                'df':df_r,'high':high,'medium':medium,
                'low':low_t,'attacks':attacks,'total':total
            }

    # ── Tab 4: Federated Learning ─────────────────────────────────────────────
    with tab4:
        st.markdown("### 🤝 Federated Learning Simulation")
        st.info("Simulates FedAvg across 3 clients without sharing raw data.")
        cr,cs = st.columns([1,3])
        with cr:
            run_fed = st.button("🚀 Run Federated Training",
                                type="primary", disabled=not is_admin)
        with cs:
            if not is_admin: st.warning("🔒 Admin only")
        fed_res = None
        if os.path.exists('federated_model/federated_results.pkl'):
            try: fed_res = joblib.load('federated_model/federated_results.pkl')
            except: pass
        if run_fed and is_admin:
            with st.spinner("Running federated training (~60-90s)..."):
                try:
                    import federated_train
                    fed_res = federated_train.run_federated_training()
                    st.success("✅ Done!"); st.rerun()
                except Exception as e: st.error(f"Error: {e}")
        if fed_res:
            st.markdown("---")
            ac = st.columns(3); icons=["🏥","🏦","📡"]
            for i,(name,icon) in enumerate(zip(fed_res["client_names"],icons)):
                with ac[i]:
                    st.markdown(f"""<div style="background:#1a1f2e;border:1px solid #2d3748;
                    border-radius:10px;padding:16px;text-align:center;">
                    <div style="font-size:32px">{icon}</div>
                    <div style="color:#60a5fa;font-weight:bold">{name}</div>
                    <div style="color:#94a3b8;font-size:12px">100 trees · data stays local ✅</div>
                    </div>""",unsafe_allow_html=True)
            st.markdown("""<div style="text-align:center;padding:12px;color:#60a5fa">
            ↓ weights only ↓<br>
            <strong style="color:#22c55e;font-size:18px">🌐 FedAvg Global Model</strong>
            </div>""",unsafe_allow_html=True)
            st.markdown("---")
            cc = st.columns(3)
            for i,(col,name,m,icon) in enumerate(zip(
                    cc,fed_res["client_names"],fed_res["client_metrics"],icons)):
                with col:
                    st.markdown(f"**{icon} {name}**")
                    st.metric("Accuracy",f"{m['accuracy']}%")
                    st.metric("F1",f"{m['f1']}%")
            st.markdown("---")
            gm=fed_res["global_metrics"]; cm2=fed_res["central_metrics"]
            p1,p2 = st.columns(2)
            with p1:
                st.markdown("**🤝 Federated**")
                st.metric("Accuracy",f"{gm['accuracy']}%",
                          delta=f"{round(gm['accuracy']-cm2['accuracy'],2):+}%")
            with p2:
                st.markdown("**🎯 Centralized**")
                st.metric("Accuracy",f"{cm2['accuracy']}%")
            st.success("✅ Privacy preserved — raw data never shared.")
        else:
            st.warning("No results yet. Click Run Federated Training.")

    # ── Tab 5: AI Threat Explainer ────────────────────────────────────────────
    with tab5:
        st.markdown("### 🔍 AI Threat Explainer (RAG)")
        if not GROQ_KEY:
            st.error("❌ GROQ_API_KEY not set.")
        else:
            ca1,cb1,cc1 = st.columns(3)
            with ca1: protocol=st.selectbox("Protocol",["tcp","udp","icmp"])
            with cb1: service=st.selectbox("Service",["private","http","ftp","telnet","smtp","ssh","imap4","mtp","discard"])
            with cc1: flag=st.selectbox("TCP Flag",["REJ","S0","SF","RSTO","RSTR"])
            pred=st.radio("Prediction",["attack","normal"],horizontal=True)
            if st.button("🤖 Explain",type="primary"):
                with st.spinner("Retrieving knowledge..."):
                    try:
                        from rag_engine import explain_attack
                        exp=explain_attack(protocol,service,flag,pred)
                        st.markdown(f"""<div style="background:#1a1f2e;border:1px solid #2d3748;
                        border-radius:10px;padding:20px;">
                        <p style="color:#e2e8f0;font-size:15px;line-height:1.7">{exp}</p>
                        </div>""",unsafe_allow_html=True)
                    except Exception as e: st.error(f"Error: {e}")

    # ── Tab 6: AI Chatbot ─────────────────────────────────────────────────────
    with tab6:
        st.markdown("### 💬 AI Security Chatbot (RAG)")
        if not GROQ_KEY:
            st.error("❌ GROQ_API_KEY not set.")
        else:
            if "chat_history" not in st.session_state:
                st.session_state["chat_history"]=[]
            for msg in st.session_state["chat_history"]:
                align = "right" if msg["role"]=="user" else "left"
                color = "#60a5fa" if msg["role"]=="user" else "#22c55e"
                label = "You" if msg["role"]=="user" else "🤖 AI"
                bg    = "#1a1f2e" if msg["role"]=="user" else "#162032"
                st.markdown(f"""<div style="background:{bg};border-radius:8px;
                padding:12px;margin:4px 0;text-align:{align};">
                <span style="color:{color}">{label}: </span>
                <span style="color:#e2e8f0">{msg['content']}</span>
                </div>""",unsafe_allow_html=True)
            user_input=st.text_input("Ask...",placeholder="What is SCCA-IDS? How does calibration work?",key="chat_input")
            cs1,cs2=st.columns([1,1])
            with cs1:
                if st.button("Send 💬",type="primary",use_container_width=True):
                    if user_input.strip():
                        with st.spinner("Thinking..."):
                            try:
                                from rag_engine import chat_with_rag
                                resp=chat_with_rag(user_input,st.session_state["chat_history"])
                                st.session_state["chat_history"].append({"role":"user","content":user_input})
                                st.session_state["chat_history"].append({"role":"assistant","content":resp})
                                st.rerun()
                            except Exception as e: st.error(f"Error: {e}")
            with cs2:
                if st.button("Clear 🗑️",use_container_width=True):
                    st.session_state["chat_history"]=[]; st.rerun()

    # ── Tab 7: AI Report ──────────────────────────────────────────────────────
    with tab7:
        st.markdown("### 📝 AI Security Report Generator")
        if not GROQ_KEY:
            st.error("❌ GROQ_API_KEY not set.")
        else:
            lc=""
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE,'r') as f: lc=f.read().strip()
            if lc:
                st.success(f"✅ {len(lc.split(chr(10)))} attack(s) in log — ready to generate.")
            else:
                st.warning("⚠️ Attack log empty. Analyze traffic first.")
            if st.button("📝 Generate Report",type="primary",disabled=not lc):
                with st.spinner("Generating security report..."):
                    try:
                        from rag_engine import analyze_attack_log
                        report=analyze_attack_log(lc)
                        st.markdown(f"""<div style="background:#1a1f2e;border:1px solid #2d3748;
                        border-radius:10px;padding:24px;">
                        <p style="color:#e2e8f0;font-size:14px;line-height:1.8;white-space:pre-wrap">{report}</p>
                        </div>""",unsafe_allow_html=True)
                        st.download_button("⬇️ Download",data=report,
                            file_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M')}.txt",
                            mime="text/plain")
                    except Exception as e: st.error(f"Error: {e}")

if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False

if st.session_state["logged_in"]:
    dashboard()
else:
    login_page()