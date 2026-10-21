import os
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, precision_recall_fscore_support
import joblib
import json

os.makedirs("data", exist_ok=True)
os.makedirs("models", exist_ok=True)

def generate_synthetic_logs(num_rows=1000):
    np.random.seed(42)
    timestamps = pd.date_range(start="2026-10-01 00:00:00", periods=num_rows, freq="min")
    source_ips = [f"192.168.1.{np.random.randint(1, 50)}" for _ in range(num_rows)]
    
    attacker_ips = ["10.0.0.99", "45.33.22.11", "185.199.108.153"]
    for i in range(int(num_rows * 0.08)):
        source_ips[np.random.randint(0, num_rows)] = np.random.choice(attacker_ips)
        
    event_types = np.random.choice(
        ["HTTP_GET", "HTTP_POST", "LOGIN_SUCCESS", "LOGIN_FAILURE", "PORT_SCAN", "SQL_INJECTION"],
        size=num_rows,
        p=[0.5, 0.2, 0.13, 0.1, 0.04, 0.03]
    )
    
    failure_counts, bytes_transferred, status_codes = [], [], []
    
    for et in event_types:
        if et == "LOGIN_FAILURE":
            failure_counts.append(np.random.randint(3, 15))
            bytes_transferred.append(np.random.randint(200, 500))
            status_codes.append(401)
        elif et in ["PORT_SCAN", "SQL_INJECTION"]:
            failure_counts.append(np.random.randint(0, 5))
            bytes_transferred.append(np.random.randint(5000, 50000))
            status_codes.append(403)
        else:
            failure_counts.append(0)
            bytes_transferred.append(np.random.randint(500, 4000))
            status_codes.append(200)

    df = pd.DataFrame({
        "timestamp": timestamps,
        "source_ip": source_ips,
        "event_type": event_types,
        "failure_count": failure_counts,
        "bytes_transferred": bytes_transferred,
        "status_code": status_codes
    })
    
    # Ground truth label (1 = Anomaly/Suspicious, 0 = Normal)
    df["is_suspicious"] = df.apply(
        lambda row: 1 if row["event_type"] in ["PORT_SCAN", "SQL_INJECTION"] or row["failure_count"] > 5 else 0,
        axis=1
    )
    
    df.to_csv("data/raw_logs.csv", index=False)
    print("[+] Generated raw logs dataset at data/raw_logs.csv")
    return df

def train_and_evaluate_model():
    df = pd.read_csv("data/raw_logs.csv")
    X = df[["failure_count", "bytes_transferred", "status_code"]]
    y = df["is_suspicious"]
    
    # Train / Unseen Test Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    model = IsolationForest(contamination=0.08, random_state=42)
    model.fit(X_train_scaled)
    
    # Predict on UNSEEN test set (-1 = Anomaly, 1 = Normal)
    test_preds_raw = model.predict(X_test_scaled)
    test_preds = np.where(test_preds_raw == -1, 1, 0)
    
    # Calculate genuine Precision, Recall, F1-Score
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, test_preds, average='binary')
    
    metrics = {
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1_score": round(float(f1), 4)
    }
    
    # Save artifacts
    joblib.dump(model, "models/isolation_forest.pkl")
    joblib.dump(scaler, "models/scaler.pkl")
    with open("models/evaluation_metrics.json", "w") as f:
        json.dump(metrics, f, indent=4)
        
    print("\n--- MODEL EVALUATION RESULTS (Unseen Test Data) ---")
    print(classification_report(y_test, test_preds, target_names=["Normal", "Suspicious"]))
    print(f"[+] Saved evaluation metrics to models/evaluation_metrics.json")

if __name__ == "__main__":
    generate_synthetic_logs()
    train_and_evaluate_model()