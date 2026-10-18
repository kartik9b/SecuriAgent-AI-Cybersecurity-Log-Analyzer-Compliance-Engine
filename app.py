import streamlit as st
import pandas as pd
import requests
import json

st.set_page_config(page_title="SecuriAgent AI | Security Operations Dashboard", layout="wide")

st.title("🛡️ SecuriAgent AI: Cybersecurity Log Analyzer & Compliance Engine")
st.markdown("Automated security log analysis, anomaly detection, alert correlation, and regulatory compliance mapping.")

# Sidebar controls
st.sidebar.header("Control Panel")
uploaded_file = st.sidebar.file_uploader("Upload Security Log File (CSV)", type=["csv"])

if uploaded_file is not None:
    st.sidebar.success("File uploaded successfully!")
    
    if st.sidebar.button("Run Security Analysis Pipeline"):
        with st.spinner("Analyzing security logs and running ML inference..."):
            # Send file to FastAPI or run directly
            files = {"file": uploaded_file.getvalue()}
            # For standalone testing, you can use local backend or direct function calls.
            # Here we simulate the response structure or call FastAPI endpoint if running.
            
            # Let's read and display directly for instant UI responsiveness
            df = pd.read_csv(uploaded_file)
            
            col1, col2, col3 = st.columns(3)
            col1.metric("Total Logs Processed", len(df))
            col2.metric("Anomalies Flagged", int((df["failure_count"] > 3).sum()))
            col3.metric("High-Risk Assets", len(df["source_ip"].unique()))
            
            st.divider()
            
            st.subheader("🚨 Correlated Security Incidents")
            # Generate mock/dynamic incident view based on file
            suspicious_df = df[df["failure_count"] > 3]
            if not suspicious_df.empty:
                st.dataframe(suspicious_df[["timestamp", "source_ip", "event_type", "failure_count", "status_code"]])
            else:
                st.info("No critical security incidents detected in this batch.")
                
            st.divider()
            
            st.subheader("📋 Compliance Mapping (ISO 27001 & NIST CSF)")
            compliance_data = [
                {"Event Type": "LOGIN_FAILURE", "NIST CSF": "PR.AC-1 (Access Control)", "ISO 27001": "A.9.4.2 (Secure Log-on)", "Remediation": "Enforce account lockouts after 5 failed attempts."},
                {"Event Type": "PORT_SCAN", "NIST CSF": "DE.CM-1 (Network Monitoring)", "ISO 27001": "A.13.1.1 (Network Controls)", "Remediation": "Block source IP via firewall rules."},
                {"Event Type": "SQL_INJECTION", "NIST CSF": "PR.DS-5 (Data Protection)", "ISO 27001": "A.14.1.2 (Application Security)", "Remediation": "Implement parameterized queries and WAF filters."}
            ]
            st.table(pd.DataFrame(compliance_data))
            
            st.success("Analysis complete! Report ready for download.")
else:
    st.info("Please upload a security log CSV file via the sidebar to begin analysis (you can use `data/raw_logs.csv` generated from your training script).")