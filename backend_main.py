from fastapi import FastAPI, UploadFile, File, HTTPException
import pandas as pd
import joblib
import os
import sys

# Add root directory to path so we can import from src
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.correlator import correlate_alerts
from src.compliance import map_to_compliance

app = FastAPI(title="SecuriAgent AI API", version="1.0.0")

# Load model and scaler
MODEL_PATH = "models/isolation_forest.pkl"
SCALER_PATH = "models/scaler.pkl"

if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
else:
    model, scaler = None, None

@app.get("/")
def home():
    return {"message": "Welcome to SecuriAgent AI Log Analysis and Compliance API"}

@app.post("/analyze-logs/")
async def analyze_logs(file: UploadFile = File(...)):
    """Uploads a security log CSV, runs ML anomaly detection, correlates alerts, and maps compliance."""
    if not model or not scaler:
        raise HTTPException(status_code=500, detail="ML model or scaler not found. Please train the model first.")
    
    try:
        # Save uploaded file temporarily
        temp_file_path = f"data/{file.filename}"
        os.makedirs("data", exist_ok=True)
        with open(temp_file_path, "wb") as buffer:
            buffer.write(await file.read())
            
        # Read log data
        df = pd.read_csv(temp_file_path)
        
        # Run ML Anomaly Detection
        features = df[["failure_count", "bytes_transferred", "status_code"]]
        X_scaled = scaler.transform(features)
        predictions = model.predict(X_scaled)
        
        # -1 indicates anomaly in Isolation Forest, 1 indicates normal
        df["anomaly_score"] = model.decision_function(X_scaled)
        df["is_ml_anomaly"] = [1 if p == -1 else 0 for p in predictions]
        
        # Run Correlator
        incidents = correlate_alerts(temp_file_path)
        
        # Extract unique event types for compliance mapping
        all_events = df["event_type"].unique().tolist()
        compliance_mappings = map_to_compliance(all_events)
        
        return {
            "status": "success",
            "total_logs_analyzed": len(df),
            "total_anomalies_detected": int(df["is_ml_anomaly"].sum()),
            "correlated_incidents": incidents,
            "compliance_mappings": compliance_mappings
        }
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error processing log file: {str(e)}")