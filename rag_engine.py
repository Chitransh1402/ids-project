"""
rag_engine.py
RAG (Retrieval-Augmented Generation) engine for the IDS project.
Uses Groq API (Llama 3) as the LLM and knowledge_base.py for retrieval.
"""

import os
from groq import Groq
from knowledge_base import get_context, retrieve
from dotenv import load_dotenv
load_dotenv()

# ── Groq client ───────────────────────────────────────────────────────────────
def get_groq_client():
    api_key = os.environ.get("GROQ_API_KEY", "")
    if not api_key:
        raise ValueError("GROQ_API_KEY not set in environment variables or .env file.")
    return Groq(api_key=api_key)


# ── Feature 1: AI Threat Explainer ────────────────────────────────────────────
def explain_attack(protocol: str, service: str, flag: str,
                   prediction: str = "attack") -> str:
    """
    Given network connection features, retrieves relevant cybersecurity
    knowledge and generates a natural language explanation of the threat.
    """
    query = f"{prediction} network intrusion protocol {protocol} service {service} flag {flag}"
    context = get_context(query, top_k=3)

    prompt = f"""You are a cybersecurity analyst assistant for an Intrusion Detection System.
A network connection has been classified as: {prediction.upper()}

Connection Details:
- Protocol: {protocol}
- Service: {service}
- TCP Flag: {flag}

Relevant cybersecurity knowledge:
{context}

Based on this information, provide a concise analysis (3-4 sentences) that:
1. Identifies the likely attack type based on the connection features
2. Explains what this attack does and why it is dangerous
3. Suggests an immediate mitigation step

Keep the response professional, clear, and actionable. Do not use markdown headers."""

    try:
        client = get_groq_client()
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=300,
            temperature=0.3,
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"AI explanation unavailable: {str(e)}"


# ── Feature 2: AI Security Chatbot ────────────────────────────────────────────
def chat_with_rag(user_message: str, chat_history: list[dict]) -> str:
    """
    Answers user questions about the IDS project, attacks, and network security
    using RAG - retrieves relevant knowledge before generating a response.
    """
    context = get_context(user_message, top_k=3)

    system_prompt = f"""You are an expert AI assistant for a Cloud-Based Intelligent Intrusion Detection System (IDS).
You help users understand network security, attack types, the NSL-KDD dataset, and the IDS system.

The IDS system details:
- Dataset: NSL-KDD (41 features, binary classification: normal/attack)
- Model: Random Forest Classifier (300 estimators, ~99% accuracy)
- Backend: Flask REST API (/predict, /health endpoints)
- Frontend: Streamlit dashboard with role-based auth (Admin/Viewer)
- Federated Learning: FedAvg across 3 simulated clients (Hospital, Bank, Telecom)
- Deployment: Docker + Render Cloud
- Email alerts: Gmail SMTP on attack detection

Relevant knowledge base context:
{context}

Answer clearly and concisely. If the question is outside your knowledge, say so honestly.
Do not use excessive markdown - keep responses conversational but informative."""

    messages = [{"role": "system", "content": system_prompt}]
    # Add chat history (last 6 messages for context window)
    for msg in chat_history[-6:]:
        messages.append(msg)
    messages.append({"role": "user", "content": user_message})

    try:
        client = get_groq_client()
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=messages,
            max_tokens=500,
            temperature=0.5,
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"Chatbot unavailable: {str(e)}"


# ── Feature 3: AI Attack Log Analyzer ─────────────────────────────────────────
def analyze_attack_log(log_contents: str) -> str:
    """
    Reads the attack log and generates a natural language security report
    summarizing detected threats, patterns, and recommendations.
    """
    if not log_contents.strip():
        return "No attack log entries found. The system has not detected any threats yet."

    # Parse log for stats
    lines = [l for l in log_contents.strip().split('\n') if l.strip()]
    total_attacks = len(lines)

    # Extract protocols and services
    protocols = {}
    services  = {}
    for line in lines:
        try:
            parts = dict(p.split('=') for p in line.split('|')[1:] if '=' in p)
            proto = parts.get('protocol', '?').strip()
            svc   = parts.get('service',  '?').strip()
            protocols[proto] = protocols.get(proto, 0) + 1
            services[svc]    = services.get(svc,   0) + 1
        except Exception:
            pass

    top_protocol = max(protocols, key=protocols.get) if protocols else "unknown"
    top_service  = max(services,  key=services.get)  if services  else "unknown"

    # Get timestamps
    timestamps = []
    for line in lines:
        try:
            ts = line[1:20]
            timestamps.append(ts)
        except Exception:
            pass
    first_attack = timestamps[0]  if timestamps else "unknown"
    last_attack  = timestamps[-1] if timestamps else "unknown"

    context = get_context(f"attack {top_protocol} {top_service} intrusion detection mitigation", top_k=2)

    prompt = f"""You are a cybersecurity analyst. Generate a professional security incident report based on the IDS attack log below.

Attack Log Summary:
- Total attacks detected: {total_attacks}
- Protocol distribution: {dict(list(protocols.items())[:5])}
- Top targeted services: {dict(list(services.items())[:5])}
- First attack: {first_attack}
- Most recent attack: {last_attack}
- Most common protocol: {top_protocol}
- Most targeted service: {top_service}

Relevant security knowledge:
{context}

Generate a professional security report with these sections:
1. Executive Summary (2-3 sentences)
2. Threat Analysis (identify likely attack types based on protocol/service patterns)
3. Risk Assessment (rate severity: Low/Medium/High and explain why)
4. Recommended Actions (3 specific mitigation steps)

Keep the report concise, professional, and actionable. Total length: 200-250 words."""

    try:
        client = get_groq_client()
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=600,
            temperature=0.4,
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"AI report generation unavailable: {str(e)}"


if __name__ == "__main__":
    # Quick tests
    print("=== Test 1: Threat Explainer ===")
    print(explain_attack("tcp", "private", "REJ"))

    print("\n=== Test 2: Chatbot ===")
    print(chat_with_rag("What is a Neptune attack?", []))

    print("\n=== Test 3: Log Analyzer ===")
    sample_log = """[2026-06-11 10:00:01] ATTACK DETECTED | protocol=tcp | service=private | flag=REJ
[2026-06-11 10:00:05] ATTACK DETECTED | protocol=tcp | service=private | flag=S0
[2026-06-11 10:00:09] ATTACK DETECTED | protocol=tcp | service=http | flag=REJ"""
    print(analyze_attack_log(sample_log))