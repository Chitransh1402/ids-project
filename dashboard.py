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

st.set_page_config(page_title="IDS Dashboard", page_icon="🛡️",
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

FEATURE_COLS = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes',
    'land','wrong_fragment','urgent','hot','num_failed_logins','logged_in',
    'num_compromised','root_shell','su_attempted','num_root','num_file_creations',
    'num_shells','num_access_files','num_outbound_cmds','is_host_login',
    'is_guest_login','count','srv_count','serror_rate','srv_serror_rate',
    'rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate',
    'srv_diff_host_rate','dst_host_count','dst_host_srv_count',
    'dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate','dst_host_serror_rate','dst_host_srv_serror_rate',
    'dst_host_rerror_rate','dst_host_srv_rerror_rate'
]

# NSL-KDD demo rows contain 41 input features plus label and difficulty.
CSV_COLS = FEATURE_COLS + ['label', 'difficulty']

# ── Helpers ───────────────────────────────────────────────────────────────────
def log_attack(protocol, service, flag):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(LOG_FILE, 'a') as f:
        f.write(f"[{timestamp}] ATTACK DETECTED | protocol={protocol} | service={service} | flag={flag}\n")

def send_email_alert(total, attacks, normal, filename="uploaded file"):
    if not SMTP_PASS: return False, "SMTP_PASSWORD not configured."
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"🚨 IDS ALERT: {attacks} Attack(s) Detected"
        msg["From"] = SMTP_SENDER; msg["To"] = ALERT_TO
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        html = f"""<html><body style="font-family:Arial;background:#0e1117;color:#e2e8f0;padding:20px;">
        <div style="max-width:600px;margin:auto;background:#1a1f2e;border-radius:12px;padding:24px;">
        <h2 style="color:#ef4444;">🚨 Intrusion Alert</h2>
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
            if username in USERS and USERS[username]["password"] == password:
                st.session_state.update({"logged_in":True,"username":username,
                                         "role":USERS[username]["role"],"chat_history":[]})
                st.rerun()
            else:
                st.error("Invalid username or password.")
        st.caption("Admin → admin / ids@2024   |   Viewer → user / network123")

# ── Dashboard ─────────────────────────────────────────────────────────────────
def dashboard():
    role     = st.session_state.get("role", "viewer")
    is_admin = (role == "admin")

    with st.sidebar:
        st.markdown("### 🛡️ IDS Dashboard")
        st.markdown(f"Logged in as **{st.session_state['username']}**")
        st.markdown(f"Role: {'🔴 Admin' if is_admin else '🟢 Viewer'}")
        st.markdown("---")
        try:
            r = requests.get(f"{API_URL}/health", timeout=30)
            r.raise_for_status()
            if r.json().get("status") != "running":
                raise RuntimeError("API did not report running status")
            st.success("✅ API Online")
        except Exception as exc:
            st.error(f"❌ API unavailable: {exc}")
        st.markdown("---")
        st.markdown("**🤖 AI (RAG)**")
        st.success("✅ Groq Connected") if GROQ_KEY else st.warning("⚠️ GROQ_API_KEY not set")
        if is_admin:
            st.markdown("**📧 Email Alerts**")
            st.success("✅ Configured") if SMTP_PASS else st.warning("⚠️ Not configured")
            if st.button("📧 Test Email"):
                ok,msg = send_email_alert(1,1,0,"test")
                st.success("Sent!") if ok else st.error(f"Failed: {msg}")
        st.markdown("---")
        if st.button("Sign Out"):
            st.session_state.clear(); st.rerun()

    st.title("🛡️ Cloud-Based Intelligent Intrusion Detection System")
    st.caption("NSL-KDD · Random Forest · Federated Learning · RAG AI · Real-time Analysis")

    tab1,tab2,tab3,tab4,tab5,tab6,tab7 = st.tabs([
        "📂 Analyze Traffic",
        "📊 Statistics & Metrics",
        "📋 Attack Log",
        "🤝 Federated Learning",
        "🔍 AI Threat Explainer",
        "💬 AI Security Chatbot",
        "📝 AI Security Report",
    ])

    # ── Tab 1: Analyze ────────────────────────────────────────────────────────
    with tab1:
        st.markdown("### Upload Network Log")
        st.info("Upload a CSV file with 41 network features. Use demo files from `demo/` folder.")
        uploaded_file = st.file_uploader("Choose a CSV file", type=["csv"])
        if uploaded_file:
            raw = pd.read_csv(uploaded_file, header=None)
            if raw.shape[1] == 43:
                raw.columns = CSV_COLS
            elif raw.shape[1] == 42:
                raw.columns = FEATURE_COLS + ['label']
                raw['difficulty'] = None
            elif raw.shape[1] == 41:
                raw.columns = FEATURE_COLS
                raw['label'] = None
                raw['difficulty'] = None
            else:
                st.error(
                    "Invalid CSV: expected 41 features, optionally followed by "
                    f"label and difficulty. Received {raw.shape[1]} columns."
                )
                st.stop()

            df = raw
            df_display = df.copy()
            filename = uploaded_file.name
            try:
                health = requests.get(f"{API_URL}/health", timeout=30)
                health.raise_for_status()
                if health.json().get("status") != "running":
                    raise RuntimeError("API did not report running status")
            except Exception as exc:
                st.error(f"❌ Flask API is not running: {exc}")
                st.stop()
            predictions = []
            progress = st.progress(0); status_text = st.empty()
            for idx, (_, row) in enumerate(df.iterrows()):
                # Send exactly the 41 training-time input features.
                payload = row[FEATURE_COLS].to_dict()
                payload = {k: float(v) if hasattr(v,'item') else v for k,v in payload.items()}
                try:
                    response = requests.post(f"{API_URL}/predict", json=payload, timeout=30)
                    response.raise_for_status()
                    result = response.json()
                    if 'prediction' not in result:
                        raise ValueError(f"Unexpected API response: {result}")

                    predictions.append(result['prediction'])
                    if result['prediction']=='attack':
                        log_attack(str(row['protocol_type']),str(row['service']),str(row['flag']))
                except Exception as exc:
                    predictions.append('error')
                    st.warning(f"Row {idx + 1} could not be classified: {exc}")
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
                st.error(f"🚨 ALERT: {attacks} malicious connection(s) detected!")
                if SMTP_PASS:
                    ok,msg = send_email_alert(total,attacks,normal,filename)
                    st.info(f"📧 Email sent to {ALERT_TO}") if ok else st.warning(f"📧 Email failed: {msg}")
            elif errors:
                st.warning(f"⚠️ {errors} row(s) could not be classified. No conclusion can be made yet.")
            else:
                st.success("✅ No attacks detected. All traffic is normal.")
            st.markdown("### Results (first 50 rows)")
            def hl(val):
                if val=='attack': return 'background-color:#7f1d1d;color:#fca5a5;'
                if val=='normal': return 'background-color:#14532d;color:#86efac;'
                return ''
            styled = df_display[['duration','protocol_type','service','flag','label','prediction']].head(50).reset_index(drop=True)
            st.dataframe(styled.style.map(hl,subset=['prediction']),use_container_width=True,hide_index=True)
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
                m4.metric("⚖️ F1 Score",f"{metrics['f1']*100:.1f}%")
            st.markdown("---")
            col1,col2=st.columns(2)
            with col1:
                st.markdown("#### Traffic Classification")
                fig1,ax1=plt.subplots(figsize=(5,4)); fig1.patch.set_facecolor('#1a1f2e'); ax1.set_facecolor('#1a1f2e')
                if normal>0 or attacks>0:
                    _,_,autotexts=ax1.pie([normal,attacks],labels=['Normal','Attack'],colors=['#22c55e','#ef4444'],autopct='%1.1f%%',startangle=90,textprops={'color':'white'})
                    for at in autotexts: at.set_color('white')
                ax1.set_title("Normal vs Attack",color='white'); st.pyplot(fig1); plt.close()
            with col2:
                st.markdown("#### Confusion Matrix")
                if metrics:
                    cm=np.array([[metrics['tn'],metrics['fp']],[metrics['fn'],metrics['tp']]])
                    fig_cm,ax_cm=plt.subplots(figsize=(5,4)); fig_cm.patch.set_facecolor('#1a1f2e'); ax_cm.set_facecolor('#1a1f2e')
                    ax_cm.imshow(cm,interpolation='nearest',cmap='RdYlGn')
                    ax_cm.set_title("Confusion Matrix",color='white'); ax_cm.set_xlabel("Predicted",color='white'); ax_cm.set_ylabel("Actual",color='white')
                    ax_cm.set_xticks([0,1]); ax_cm.set_yticks([0,1])
                    ax_cm.set_xticklabels(['Normal','Attack'],color='white'); ax_cm.set_yticklabels(['Normal','Attack'],color='white')
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
                    fig2,ax2=plt.subplots(figsize=(5,4)); fig2.patch.set_facecolor('#1a1f2e'); ax2.set_facecolor('#1a1f2e')
                    ax2.bar(pc.index,pc.values,color=['#ef4444','#f97316','#eab308'][:len(pc)])
                    ax2.set_xlabel("Protocol",color='white'); ax2.set_ylabel("Count",color='white'); ax2.tick_params(colors='white')
                    st.pyplot(fig2); plt.close()
                else: st.success("No attacks.")
            with col4:
                st.markdown("#### Top 10 Targeted Services")
                if not attack_rows.empty:
                    sc=attack_rows['service'].value_counts().head(10)
                    fig3,ax3=plt.subplots(figsize=(5,4)); fig3.patch.set_facecolor('#1a1f2e'); ax3.set_facecolor('#1a1f2e')
                    ax3.barh(sc.index[::-1],sc.values[::-1],color='#ef4444'); ax3.tick_params(colors='white')
                    st.pyplot(fig3); plt.close()

    # ── Tab 3: Attack Log ─────────────────────────────────────────────────────
    with tab3:
        st.markdown("### Attack Log")
        ca,cb=st.columns([3,1])
        with cb:
            if is_admin:
                if st.button("🗑️ Clear Log"): open(LOG_FILE,'w').close(); st.success("Cleared."); st.rerun()
            else: st.caption("🔒 Admin only")
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE,'r') as f: lc=f.read().strip()
            if lc:
                lines=lc.split('\n'); st.caption(f"{len(lines)} attack(s) recorded"); st.code(lc,language=None)
            else: st.info("No attacks logged yet.")
        else: st.info("No log file found yet.")

    # ── Tab 4: Federated Learning ─────────────────────────────────────────────
    with tab4:
        st.markdown("### 🤝 Federated Learning Simulation")
        st.info("Simulates FedAvg across 3 clients (Hospital, Bank, Telecom) without sharing raw data.")
        col_r,col_s=st.columns([1,3])
        with col_r:
            run_fed=st.button("🚀 Run Federated Training",type="primary",disabled=not is_admin)
        with col_s:
            if not is_admin: st.warning("🔒 Admin only")
        results=None
        if os.path.exists('federated_model/federated_results.pkl'):
            try: results=joblib.load('federated_model/federated_results.pkl')
            except: pass
        if run_fed and is_admin:
            with st.spinner("Running federated training (~60-90 seconds)..."):
                try:
                    import federated_train
                    results=federated_train.run_federated_training()
                    st.success("✅ Federated training complete!"); st.rerun()
                except Exception as e: st.error(f"Error: {e}")
        if results:
            st.markdown("---")
            ac=st.columns(3); icons=["🏥","🏦","📡"]
            for i,(name,icon) in enumerate(zip(results["client_names"],icons)):
                with ac[i]:
                    st.markdown(f"""<div style="background:#1a1f2e;border:1px solid #2d3748;border-radius:10px;padding:16px;text-align:center;">
                    <div style="font-size:32px">{icon}</div><div style="color:#60a5fa;font-weight:bold">{name}</div>
                    <div style="color:#94a3b8;font-size:12px">100 trees · data stays local ✅</div></div>""",unsafe_allow_html=True)
            st.markdown("""<div style="text-align:center;padding:12px;color:#60a5fa">↓ weights only ↓<br>
            <strong style="color:#22c55e;font-size:18px">🌐 FedAvg Global Model</strong></div>""",unsafe_allow_html=True)
            st.markdown("---")
            st.markdown("#### Per-Client Performance")
            cc=st.columns(3)
            for i,(col,name,m,icon) in enumerate(zip(cc,results["client_names"],results["client_metrics"],icons)):
                with col:
                    st.markdown(f"**{icon} {name}**")
                    st.metric("Accuracy",f"{m['accuracy']}%"); st.metric("F1",f"{m['f1']}%")
            st.markdown("---")
            st.markdown("#### ⚖️ Federated vs Centralized")
            gm=results["global_metrics"]; cc2=results["central_metrics"]
            cp1,cp2=st.columns(2)
            with cp1:
                st.markdown("**🤝 Federated (FedAvg)**")
                st.metric("Accuracy",f"{gm['accuracy']}%",delta=f"{round(gm['accuracy']-cc2['accuracy'],2):+}% vs centralized")
                st.metric("F1",f"{gm['f1']}%")
            with cp2:
                st.markdown("**🎯 Centralized (Baseline)**")
                st.metric("Accuracy",f"{cc2['accuracy']}%"); st.metric("F1",f"{cc2['f1']}%")
            fig,ax=plt.subplots(figsize=(10,4)); fig.patch.set_facecolor("#1a1f2e"); ax.set_facecolor("#1a1f2e")
            labels=[f"Client 1\n{results['client_names'][0]}",f"Client 2\n{results['client_names'][1]}",
                    f"Client 3\n{results['client_names'][2]}","Federated\n(FedAvg)","Centralized\n(Baseline)"]
            values=[results["client_metrics"][0]["accuracy"],results["client_metrics"][1]["accuracy"],
                    results["client_metrics"][2]["accuracy"],gm["accuracy"],cc2["accuracy"]]
            colors=["#60A5FA","#60A5FA","#60A5FA","#22C55E","#F59E0B"]
            bars=ax.bar(labels,values,color=colors,width=0.5); ax.set_ylim(min(values)-5,101)
            ax.set_ylabel("Accuracy (%)",color="white"); ax.tick_params(colors="white")
            ax.set_title("Accuracy Comparison",color="white")
            for spine in ax.spines.values(): spine.set_edgecolor("#2d3748")
            for bar,val in zip(bars,values):
                ax.text(bar.get_x()+bar.get_width()/2,bar.get_height()+0.2,f"{val}%",ha="center",color="white",fontsize=11,fontweight="bold")
            st.pyplot(fig); plt.close()
            st.success("✅ Privacy preserved — raw data never shared between clients.")
        else:
            st.warning("No results yet. Click Run Federated Training (Admin required).")

    # ── Tab 5: AI Threat Explainer ────────────────────────────────────────────
    with tab5:
        st.markdown("### 🔍 AI Threat Explainer")
        st.info("Enter network connection features and the AI will explain the detected threat using RAG.")
        if not GROQ_KEY:
            st.error("❌ GROQ_API_KEY not set. Add it to your .env file.")
        else:
            col_a,col_b,col_c=st.columns(3)
            with col_a:
                protocol=st.selectbox("Protocol",["tcp","udp","icmp"])
            with col_b:
                service=st.selectbox("Service",["private","http","ftp","telnet","smtp","ssh","imap4","mtp","discard","courier","systat","iso_tsap","ldap","domain"])
            with col_c:
                flag=st.selectbox("TCP Flag",["REJ","S0","SF","RSTO","RSTR","SH","S1","S2","OTH"])
            prediction=st.radio("Prediction",["attack","normal"],horizontal=True)
            if st.button("🤖 Explain This Threat",type="primary"):
                with st.spinner("Retrieving knowledge and generating explanation..."):
                    try:
                        from rag_engine import explain_attack
                        st.session_state["threat_explanation"] = explain_attack(
                            protocol, service, flag, prediction
                        )
                    except Exception as e:
                        st.session_state["threat_explanation"] = f"AI explanation unavailable: {e}"

            if "threat_explanation" in st.session_state:
                st.markdown("---")
                st.markdown("#### 🤖 AI Analysis")
                st.info(st.session_state["threat_explanation"])
                st.caption("💡 This explanation is generated using RAG (Retrieval-Augmented Generation) — "
                           "the AI retrieves relevant cybersecurity knowledge before generating the response.")
            # Also show last results if available
            if 'last_results' in st.session_state:
                st.markdown("---")
                st.markdown("#### 🔍 Auto-Explain Last Detected Attacks")
                df_res=st.session_state['last_results']['df']
                attack_rows=df_res[df_res['prediction']=='attack'].head(3)
                if not attack_rows.empty:
                    if st.button("🤖 Explain First 3 Attacks from Last Analysis"):
                        from rag_engine import explain_attack
                        for i,(idx,row) in enumerate(attack_rows.iterrows()):
                            with st.spinner(f"Explaining attack {i+1}/3..."):
                                exp=explain_attack(str(row['protocol_type']),str(row['service']),str(row['flag']))
                                st.markdown(f"**🚨 Attack {i+1}** — "
                                            f"protocol={row['protocol_type']}, "
                                            f"service={row['service']}, flag={row['flag']}")
                                st.info(exp)
                else:
                    st.info("No attacks found in last analysis.")

    # ── Tab 6: AI Security Chatbot ────────────────────────────────────────────
    with tab6:
        st.markdown("### 💬 AI Security Chatbot")
        st.info("Ask anything about network security, attack types, NSL-KDD dataset, or this IDS project.")
        if not GROQ_KEY:
            st.error("❌ GROQ_API_KEY not set. Add it to your .env file.")
        else:
            if "chat_history" not in st.session_state:
                st.session_state["chat_history"]=[]
            # Display chat history
            for msg in st.session_state["chat_history"]:
                if msg["role"]=="user":
                    st.markdown(f"""<div style="background:#1a1f2e;border-radius:8px;padding:12px;margin:4px 0;text-align:right;">
                    <span style="color:#60a5fa">You: </span><span style="color:#e2e8f0">{msg['content']}</span></div>""",unsafe_allow_html=True)
                else:
                    st.markdown(f"""<div style="background:#162032;border-radius:8px;padding:12px;margin:4px 0;">
                    <span style="color:#22c55e">🤖 AI: </span><span style="color:#e2e8f0">{msg['content']}</span></div>""",unsafe_allow_html=True)
            # Input
            user_input=st.text_input("Ask a question...",placeholder="e.g. What is a Neptune attack? How does FedAvg work?",key="chat_input")
            col_send,col_clear=st.columns([1,1])
            with col_send:
                if st.button("Send 💬",type="primary",use_container_width=True):
                    if user_input.strip():
                        with st.spinner("Thinking..."):
                            try:
                                from rag_engine import chat_with_rag
                                response=chat_with_rag(user_input,st.session_state["chat_history"])
                                st.session_state["chat_history"].append({"role":"user","content":user_input})
                                st.session_state["chat_history"].append({"role":"assistant","content":response})
                                st.rerun()
                            except Exception as e:
                                st.error(f"Error: {e}")
            with col_clear:
                if st.button("Clear Chat 🗑️",use_container_width=True):
                    st.session_state["chat_history"]=[]; st.rerun()
            st.markdown("---")
            st.markdown("**Suggested questions:**")
            suggested=["What is a Neptune DoS attack?","How does Random Forest work for IDS?",
                       "What is Federated Learning?","Explain the NSL-KDD features",
                       "What does flag REJ mean?","How to mitigate probe attacks?"]
            scols=st.columns(3)
            for i,q in enumerate(suggested):
                with scols[i%3]:
                    if st.button(q,key=f"sq_{i}"):
                        with st.spinner("Thinking..."):
                            from rag_engine import chat_with_rag
                            response=chat_with_rag(q,st.session_state["chat_history"])
                            st.session_state["chat_history"].append({"role":"user","content":q})
                            st.session_state["chat_history"].append({"role":"assistant","content":response})
                            st.rerun()

    # ── Tab 7: AI Security Report ─────────────────────────────────────────────
    with tab7:
        st.markdown("### 📝 AI Security Report Generator")
        st.info("Generates a professional natural language security report from the attack log using RAG + Groq AI.")
        if not GROQ_KEY:
            st.error("❌ GROQ_API_KEY not set. Add it to your .env file.")
        else:
            log_contents=""
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE,'r') as f: log_contents=f.read().strip()
            if log_contents:
                lines=log_contents.split('\n')
                st.success(f"✅ Found {len(lines)} attack(s) in log — ready to generate report.")
            else:
                st.warning("⚠️ Attack log is empty. Analyze some traffic first to populate the log.")
            if st.button("📝 Generate AI Security Report",type="primary",disabled=not log_contents):
                with st.spinner("Retrieving knowledge and generating security report..."):
                    try:
                        from rag_engine import analyze_attack_log
                        st.session_state["security_report"] = analyze_attack_log(log_contents)
                    except Exception as e:
                        st.session_state["security_report"] = f"AI report generation unavailable: {e}"

            if "security_report" in st.session_state:
                report = st.session_state["security_report"]
                st.markdown("---")
                st.markdown("#### 📋 AI-Generated Security Report")
                st.text_area("Generated report", value=report, height=320, disabled=True)
                st.download_button("⬇️ Download Report",data=report,
                                   file_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M')}.txt",
                                   mime="text/plain")
                st.caption("💡 This report is generated using RAG — the AI retrieves cybersecurity knowledge "
                           "relevant to the detected attack patterns before generating recommendations.")

# ── Entry ─────────────────────────────────────────────────────────────────────
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False

if st.session_state["logged_in"]:
    dashboard()
else:
    login_page()
