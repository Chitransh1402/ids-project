"""
rag_engine.py
RAG (Retrieval-Augmented Generation) engine for the IDS project.
Uses Groq API and knowledge_base.py for retrieval.
"""

import os
from groq import Groq
from knowledge_base import get_context
from dotenv import load_dotenv

load_dotenv()

# Current Groq model. You can override it in .env or Render:
# GROQ_MODEL=openai/gpt-oss-20b
GROQ_MODEL = os.environ.get("GROQ_MODEL", "openai/gpt-oss-20b")


def get_groq_client():
    """Create a Groq client using the GROQ_API_KEY environment variable."""
    api_key = os.environ.get("GROQ_API_KEY", "")

    if not api_key:
        raise ValueError("GROQ_API_KEY not set in environment variables or .env file.")

    return Groq(api_key=api_key)


def get_ai_response(messages, max_tokens=700, temperature=0.4):
    """
    Send a request to Groq and return readable response text.
    Low reasoning effort prevents the model from using all output tokens
    internally and returning a blank final response.
    """
    client = get_groq_client()

    response = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=messages,
        max_tokens=max_tokens,
        temperature=temperature,
        reasoning_effort="low",
        include_reasoning=False,
    )

    content = response.choices[0].message.content

    if not content or not str(content).strip():
        return (
            "The AI model returned an empty response. "
            "Please try again in a few seconds."
        )

    return str(content).strip()


def explain_attack(protocol: str, service: str, flag: str,
                   prediction: str = "attack") -> str:
    """Generate a RAG-grounded explanation for selected traffic features."""

    query = (
        f"{prediction} network intrusion protocol {protocol} "
        f"service {service} flag {flag}"
    )
    context = get_context(query, top_k=3)

    prompt = f"""You are a cybersecurity analyst assistant for an Intrusion Detection System.

A network connection has been classified as: {prediction.upper()}

Connection Details:
- Protocol: {protocol}
- Service: {service}
- TCP Flag: {flag}

Relevant cybersecurity knowledge:
{context}

Based on this information, provide a concise analysis in 3-4 sentences:
1. Identify the likely attack type based on the connection features.
2. Explain what this attack does and why it is dangerous.
3. Suggest one immediate mitigation step.

Keep the response professional, clear, and actionable.
Do not use markdown headers."""

    try:
        return get_ai_response(
            messages=[{"role": "user", "content": prompt}],
            max_tokens=700,
            temperature=0.3,
        )
    except Exception as e:
        return f"AI explanation unavailable: {str(e)}"


def chat_with_rag(user_message: str, chat_history: list[dict]) -> str:
    """Answer IDS and cybersecurity questions using RAG."""

    context = get_context(user_message, top_k=3)

    system_prompt = f"""You are an expert AI assistant for a Cloud-Based Intelligent Intrusion Detection System (IDS).

You help users understand network security, attack types, the NSL-KDD dataset, and this IDS system.

System details:
- Dataset: NSL-KDD; 41 network features; binary classification: normal or attack
- Model: Random Forest Classifier
- Backend: Flask REST API with /predict and /health
- Frontend: Streamlit dashboard with Admin and Viewer roles
- Federated Learning: simulation across Hospital, Bank, and Telecom clients
- Deployment: Docker and Render
- Email alerts: Gmail SMTP after attack detection

Relevant knowledge base context:
{context}

Answer clearly and concisely. If the question is outside your knowledge, say so honestly.
Do not use excessive markdown."""

    messages = [{"role": "system", "content": system_prompt}]
    messages.extend(chat_history[-6:])
    messages.append({"role": "user", "content": user_message})

    try:
        return get_ai_response(
            messages=messages,
            max_tokens=700,
            temperature=0.5,
        )
    except Exception as e:
        return f"Chatbot unavailable: {str(e)}"


def analyze_attack_log(log_contents: str) -> str:
    """Generate a RAG-grounded incident report from the IDS attack log."""

    if not log_contents.strip():
        return "No attack log entries found. Analyze attack traffic first."

    lines = [line for line in log_contents.strip().split("\n") if line.strip()]
    total_attacks = len(lines)

    protocols = {}
    services = {}

    for line in lines:
        try:
            parts = dict(
                part.split("=", 1)
                for part in line.split("|")[1:]
                if "=" in part
            )

            protocol = parts.get("protocol", "?").strip()
            service = parts.get("service", "?").strip()

            protocols[protocol] = protocols.get(protocol, 0) + 1
            services[service] = services.get(service, 0) + 1
        except Exception:
            pass

    top_protocol = max(protocols, key=protocols.get) if protocols else "unknown"
    top_service = max(services, key=services.get) if services else "unknown"

    timestamps = [line[1:20] for line in lines if len(line) >= 20]
    first_attack = timestamps[0] if timestamps else "unknown"
    last_attack = timestamps[-1] if timestamps else "unknown"

    context = get_context(
        f"attack {top_protocol} {top_service} intrusion detection mitigation",
        top_k=2,
    )

    prompt = f"""You are a cybersecurity analyst. Generate a professional security incident report using this IDS attack-log summary.

Attack Log Summary:
- Total attacks detected: {total_attacks}
- Protocol distribution: {dict(list(protocols.items())[:5])}
- Targeted services: {dict(list(services.items())[:5])}
- First attack: {first_attack}
- Most recent attack: {last_attack}
- Most common protocol: {top_protocol}
- Most targeted service: {top_service}

Relevant security knowledge:
{context}

Write a concise, professional report with these sections:
1. Executive Summary
2. Threat Analysis
3. Risk Assessment
4. Recommended Actions

Include three specific mitigation actions.
Keep the total report around 200-250 words."""

    try:
        return get_ai_response(
            messages=[{"role": "user", "content": prompt}],
            max_tokens=1200,
            temperature=0.4,
        )
    except Exception as e:
        return f"AI report generation unavailable: {str(e)}"


if __name__ == "__main__":
    print("=== Threat Explainer Test ===")
    print(explain_attack("tcp", "private", "REJ"))

    print("\n=== Chatbot Test ===")
    print(chat_with_rag("What is a Neptune attack?", []))

    print("\n=== Report Test ===")
    sample_log = """[2026-06-11 10:00:01] ATTACK DETECTED | protocol=tcp | service=private | flag=REJ
[2026-06-11 10:00:05] ATTACK DETECTED | protocol=tcp | service=private | flag=S0
[2026-06-11 10:00:09] ATTACK DETECTED | protocol=tcp | service=http | flag=REJ"""

    print(analyze_attack_log(sample_log))