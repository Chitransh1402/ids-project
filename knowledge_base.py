"""
knowledge_base.py
RAG Knowledge Base for the IDS project.
Contains cybersecurity documents used for retrieval-augmented generation.
"""

# ── Knowledge Base Documents ──────────────────────────────────────────────────
DOCUMENTS = [
    {
        "id": "nsl_kdd_overview",
        "title": "NSL-KDD Dataset Overview",
        "content": """The NSL-KDD dataset is the standard benchmark for evaluating intrusion detection systems.
It is an improved version of the original KDD Cup 1999 dataset with duplicate records removed.
The dataset contains 41 features per network connection record and uses binary labels: normal or attack.
Training set (KDDTrain+) has 125,973 records. Test set (KDDTest+) has 22,544 records.
The 41 features are divided into basic features (duration, protocol_type, service, flag, src_bytes, dst_bytes),
content features (num_failed_logins, logged_in, num_compromised, root_shell, su_attempted),
and traffic features (count, srv_count, serror_rate, rerror_rate, same_srv_rate, diff_srv_rate).
Three categorical features require encoding: protocol_type (tcp/udp/icmp), service (http/ftp/telnet etc), flag (SF/S0/REJ etc)."""
    },
    {
        "id": "dos_attacks",
        "title": "Denial of Service (DoS) Attacks",
        "content": """DoS attacks attempt to make a machine or network resource unavailable to its intended users.
Neptune attack: SYN flood attack that sends a flood of TCP SYN packets to overwhelm the target server.
The server allocates resources for each half-open connection, eventually running out of memory.
Smurf attack: ICMP broadcast amplification attack. Attacker sends ICMP ping to broadcast address with spoofed source IP.
All hosts on network reply to the victim, flooding it with traffic.
Pod (Ping of Death): Sends oversized ICMP packets to crash the target system.
Teardrop: Sends fragmented IP packets with overlapping offsets to crash the OS during reassembly.
Back attack: Exploits Apache web server vulnerability by sending requests with many forward slashes.
Land attack: Sends TCP SYN packet with identical source and destination IP/port, causing infinite loop.
Mitigation strategies: Rate limiting, SYN cookies, firewall rules, traffic filtering, load balancing."""
    },
    {
        "id": "probe_attacks",
        "title": "Probe/Reconnaissance Attacks",
        "content": """Probe attacks scan networks and systems to gather information for future attacks.
Ipsweep: ICMP ping sweep to discover active hosts on a network by sending pings to multiple IPs.
Portsweep: TCP/UDP port sweep to identify open services on a target host.
Nmap: Network mapper tool that performs OS detection, service version detection, and port scanning.
Satan: Security Administrator Tool for Analyzing Networks - scans for known vulnerabilities.
Mscan: Multi-scan tool that checks for multiple vulnerabilities simultaneously.
Saint: Security Administrator's Integrated Network Tool - updated version of SATAN.
Characteristics: Low traffic volume per target, spread across many destination IPs or ports,
sequential or randomized scanning patterns, often precede actual exploitation attacks.
Mitigation: IDS alerts, firewall rules blocking unused ports, network segmentation, honeypots."""
    },
    {
        "id": "r2l_attacks",
        "title": "Remote to Local (R2L) Attacks",
        "content": """R2L attacks occur when an attacker without a local account gains local access to a system remotely.
FTP_write: Exploits anonymous FTP access to write files to the server's file system.
Guess_passwd: Brute force or dictionary attack against user passwords via login services.
Imap: Exploits vulnerabilities in the IMAP email protocol to gain unauthorized access.
Phf: Exploits the phf CGI script on web servers to execute arbitrary commands.
Multihop: Attacker uses one compromised machine to attack another, chaining multiple hops.
Warezclient/Warezmaster: Using FTP to illegally download/distribute copyrighted software.
Spy: Gathering confidential information through network eavesdropping.
Characteristics: Typically involves authentication failures, unusual login times, access from foreign IPs.
Mitigation: Strong password policies, multi-factor authentication, intrusion detection, access logging."""
    },
    {
        "id": "u2r_attacks",
        "title": "User to Root (U2R) Attacks",
        "content": """U2R attacks involve an attacker who has local user access attempting to gain root/admin privileges.
Buffer_overflow: Exploits software vulnerability by writing more data than a buffer can hold, overwriting memory.
Rootkit: Malicious software designed to hide its presence and maintain privileged access to a system.
Loadmodule: Loading a malicious kernel module to gain root-level access.
Perl: Using Perl scripts to exploit setuid vulnerabilities to gain elevated privileges.
Sqlattack: SQL injection to gain database administrator access and potentially OS-level access.
Xterm: Exploiting the xterm terminal emulator to gain root privileges.
Characteristics: These are the most dangerous attacks, often preceded by successful R2L or social engineering.
Low frequency makes them hard to detect statistically. Require deep system call monitoring.
Mitigation: Principle of least privilege, kernel hardening, system call monitoring, regular patching."""
    },
    {
        "id": "random_forest",
        "title": "Random Forest Algorithm for IDS",
        "content": """Random Forest is an ensemble learning algorithm that builds multiple decision trees and aggregates predictions.
Each tree is trained on a random bootstrap sample of training data (bagging technique).
At each node split, only a random subset of features is considered (feature randomness).
For classification, final prediction is majority vote across all trees.
In our IDS project: 300 estimators, class_weight=balanced to handle class imbalance.
Advantages for IDS: Handles high-dimensional data (41 features), robust to overfitting,
resistant to noise, provides feature importance scores, no need for feature scaling strictly,
handles both numerical and categorical features, fast inference time.
Performance on NSL-KDD: ~99% accuracy, ~99% precision, ~98% recall, ~98% F1-score.
Feature importance: src_bytes, dst_bytes, count, srv_count are typically the most important features."""
    },
    {
        "id": "federated_learning",
        "title": "Federated Learning in IDS",
        "content": """Federated Learning is a machine learning approach where the model is trained across multiple decentralized devices.
Raw data never leaves the local device - only model updates (gradients or weights) are shared.
In our IDS simulation: NSL-KDD dataset split into 3 partitions simulating Hospital, Bank, Telecom networks.
FedAvg algorithm: Each client trains locally, sends model weights, central server averages them.
Privacy advantage: Network traffic logs are sensitive - organizations cannot legally share raw data.
Federated approach allows collective intelligence without data privacy violations.
FedAvg aggregation: Global model = weighted average of local model parameters.
Our implementation: 100 trees per client, aggregated to 300-tree global model.
Trade-off: Federated model slightly lower accuracy (~98%) vs centralized (~99%) but preserves privacy.
Real-world applications: IoT security, healthcare network monitoring, banking fraud detection."""
    },
    {
        "id": "network_features",
        "title": "NSL-KDD Network Features Explained",
        "content": """duration: Length in seconds of the network connection.
protocol_type: Network protocol used - tcp (Transmission Control Protocol), udp (User Datagram Protocol), icmp (Internet Control Message Protocol).
service: Network service on destination - http (web), ftp (file transfer), smtp (email), ssh (secure shell), telnet (remote login).
flag: Status of the connection - SF (normal established), S0 (connection attempt, no response), REJ (connection rejected), RSTO (reset by originator), RSTR (reset by responder).
src_bytes: Number of data bytes sent from source to destination.
dst_bytes: Number of data bytes sent from destination to source.
land: 1 if source and destination IPs and ports are the same (land attack indicator), 0 otherwise.
logged_in: 1 if successfully logged in, 0 otherwise.
num_failed_logins: Number of failed login attempts.
root_shell: 1 if root shell obtained, 0 otherwise.
serror_rate: Percentage of connections with SYN errors to the same host in last 2 seconds.
rerror_rate: Percentage of connections with REJ errors to the same host in last 2 seconds.
count: Number of connections to the same host in the last 2 seconds.
srv_count: Number of connections to the same service in the last 2 seconds."""
    },
    {
        "id": "mitigation_strategies",
        "title": "IDS Mitigation and Response Strategies",
        "content": """When an intrusion is detected, the following response strategies should be considered:
Immediate response: Isolate affected systems, block suspicious IP addresses, capture network traffic for forensics.
DoS attacks: Implement rate limiting, use SYN cookies, deploy traffic scrubbing, contact ISP for upstream filtering.
Probe attacks: Block scanning IPs at firewall, enable port knocking, use honeypots to gather attacker intelligence.
R2L attacks: Force password resets, enable MFA, review access logs, patch exploited services immediately.
U2R attacks: Revoke all user sessions, audit system for rootkits, restore from clean backup if compromised.
General best practices: Network segmentation (DMZ), regular security audits, patch management,
security awareness training, incident response plan, backup and disaster recovery.
SIEM integration: Feed IDS alerts into Security Information and Event Management system for correlation.
Threat intelligence: Share indicators of compromise (IOCs) with security community."""
    },
    {
        "id": "system_architecture",
        "title": "IDS System Architecture",
        "content": """Our Cloud-Based IDS uses a three-tier microservices architecture.
Frontend: Streamlit dashboard with role-based authentication (Admin/Viewer roles).
Admin role: Full access - can clear logs, run federated training, test email alerts.
Viewer role: Read-only access - can view results but cannot modify system state.
Backend: Flask REST API exposing /predict and /health endpoints over HTTPS.
/predict endpoint: Accepts 41 network features as JSON, returns prediction (normal/attack) and alert flag.
/health endpoint: Returns API status and model name for health monitoring.
ML Layer: Random Forest model stored as model/ids_model.pkl, loaded at API startup.
Preprocessing: Categorical encoding + StandardScaler normalization applied before inference.
Alert system: Gmail SMTP sends HTML email when attacks detected. Attack log written to alerts.log.
Deployment: Flask API as Docker container on Render. Dashboard as Python web service on Render.
GitHub: Source code at github.com/Chitransh1402/ids-project2.O"""
    }
]

# ── Simple keyword-based retrieval ────────────────────────────────────────────
def retrieve(query: str, top_k: int = 3) -> list[dict]:
    """
    Simple TF-based retrieval: score documents by keyword overlap with query.
    Returns top_k most relevant documents.
    """
    query_words = set(query.lower().split())
    scores = []

    for doc in DOCUMENTS:
        text = (doc["title"] + " " + doc["content"]).lower()
        # Count query word matches in document
        score = sum(1 for word in query_words if word in text)
        # Bonus for title match
        title_words = set(doc["title"].lower().split())
        title_score = len(query_words & title_words) * 3
        scores.append((score + title_score, doc))

    scores.sort(key=lambda x: x[0], reverse=True)
    return [doc for _, doc in scores[:top_k]]


def get_context(query: str, top_k: int = 3) -> str:
    """Retrieve relevant documents and format as context string."""
    docs = retrieve(query, top_k)
    context_parts = []
    for doc in docs:
        context_parts.append(f"[{doc['title']}]\n{doc['content']}")
    return "\n\n".join(context_parts)


def get_all_document_titles() -> list[str]:
    """Return list of all document titles in the knowledge base."""
    return [doc["title"] for doc in DOCUMENTS]


if __name__ == "__main__":
    # Test retrieval
    test_query = "neptune attack dos flooding"
    print(f"Query: {test_query}")
    print(f"Retrieved documents:")
    for doc in retrieve(test_query):
        print(f"  - {doc['title']}")