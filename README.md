# SecuriAgent-AI-Cybersecurity-Log-Analyzer-Compliance-Engine
Automated security log analysis, anomaly detection, alert correlation, and regulatory compliance mapping.

# 🛡️ SecuriAgent AI: Cybersecurity Log Analyzer & Compliance Engine

An end-to-end intelligent cybersecurity log analysis, anomaly detection, alert correlation, and regulatory compliance mapping system developed as a practical technical assessment prototype.

---

## 📋 Project Overview & Objectives
Modern security operations center (SOC) teams face high alert volumes and manual bottlenecks when analyzing fragmented logs. **SecuriAgent AI** automates this workflow by ingesting security logs, applying machine learning for anomaly detection, correlating multi-stage alerts, mapping threats to compliance controls (**ISO 27001** and **NIST CSF**), and serving results via a high-performance backend API and interactive dashboard.

---

## 🛠️ Project Architecture & Task Mapping

The project fulfills all 5 core tasks outlined in the technical assessment:

* **Task 1: Dataset Preparation & Model Training (`src/model.py`)**
  * Generates and cleans synthetic cybersecurity assessment logs (`data/raw_logs.csv`) containing normal traffic alongside attack patterns (brute-force login failures, port scans, and SQL injections).
  * Trains an **Isolation Forest** unsupervised anomaly detection model using engineered numerical features (`failure_count`, `bytes_transferred`, `status_code`).
* **Task 2: Security Log Analysis & Alert Correlation (`src/correlator.py`)**
  * Groups isolated log events into cohesive security incidents based on source IPs, event types, timestamp windows, and severity ratings (`MEDIUM`, `HIGH`, `CRITICAL`).
* **Task 3: Compliance Mapping Engine (`src/compliance.py`)**
  * Bridges technical threats to regulatory standards, mapping findings directly to **NIST CSF** and **ISO 27001** controls complete with risk levels and automated remediation guidance.
* **Task 4: Data Connectors & Backend API (`backend/main.py`)**
  * Built using **FastAPI** to ingest log files, run ML inference, perform alert correlation, and return structured JSON payloads with built-in input validation and error handling.
* **Task 5: Reporting & Presentation (`app.py`)**
  * Powered by **Streamlit**, providing a professional interactive dashboard for security analysts to upload logs, inspect real-time anomaly metrics, review correlated incidents, and explore compliance tables[cite: 2].

---

## 📂 Repository Structure
```text
securiagent-ai/
│
├── data/
│   └── raw_logs.csv                 # Generated synthetic security assessment logs
│
├── models/
│   ├── isolation_forest.pkl         # Trained anomaly detection model
│   └── scaler.pkl                   # Feature standard scaler
│
├── src/
│   ├── __init__.py
│   ├── preprocessing.py             # Log cleaning & feature extraction pipeline
│   ├── model.py                     # ML training script (Isolation Forest)
│   ├── correlator.py                # Alert clustering & incident grouping logic
│   └── compliance.py                # NIST CSF & ISO 27001 mapping framework
│
├── backend/
│   └── main.py                      # FastAPI backend application endpoints
│
├── app.py                           # Streamlit interactive user interface
├── requirements.txt                 # Python project dependencies
└── README.md                        # Project documentation
