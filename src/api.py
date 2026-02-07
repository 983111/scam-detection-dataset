from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import joblib
import pandas as pd
# Import your feature extractor
from make_scam_urls import extract_features

# Initialize App
app = FastAPI(title="Stremini AI - Scam Detector API")

# Load Model
MODEL_PATH = "../models/scam_detector.pkl"
try:
    model = joblib.load(MODEL_PATH)
    print("✅ Model loaded successfully")
except Exception as e:
    print(f"❌ Critical Error: Model not found at {MODEL_PATH}")
    model = None

# Define Request Format
class URLRequest(BaseModel):
    url: str

@app.get("/")
def home():
    return {"status": "online", "system": "Stremini Scam Detector"}

@app.post("/scan")
def scan_url(request: URLRequest):
    if not model:
        raise HTTPException(status_code=500, detail="Model not loaded")
    
    # 1. Extract Features
    features = extract_features(request.url)
    if not features:
        raise HTTPException(status_code=400, detail="Invalid URL format")

    # 2. Prepare Data
    # Ensure columns match training data exactly
    feature_cols = [
        'url_length', 'domain_length', 'path_length', 'query_length',
        'num_dots', 'num_hyphens', 'num_digits', 'num_special_chars',
        'has_ip', 'is_https', 'has_php', 'has_html', 'has_exe'
    ]
    
    df = pd.DataFrame([features])
    
    # Fill missing cols with 0 if any (safety check)
    for col in feature_cols:
        if col not in df.columns:
            df[col] = 0
            
    X = df[feature_cols]

    # 3. Predict
    is_scam = int(model.predict(X)[0])
    probability = model.predict_proba(X)[0][1] # Probability of being Malicious (1)

    return {
        "url": request.url,
        "is_scam": bool(is_scam),
        "confidence_score": float(f"{probability:.4f}"),
        "risk_level": "CRITICAL" if probability > 0.8 else "SAFE" if probability < 0.5 else "SUSPICIOUS"
    }

# To run: uvicorn api:app --reload