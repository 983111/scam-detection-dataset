import joblib
import pandas as pd
import sys
# Import the exact same feature extractor used during training
from make_scam_urls import extract_features

# Configuration
MODEL_PATH = "../models/scam_detector.pkl"

def load_model():
    try:
        model = joblib.load(MODEL_PATH)
        return model
    except FileNotFoundError:
        print(f"❌ Model file not found at {MODEL_PATH}")
        return None

def predict(url):
    model = load_model()
    if not model: return

    print(f"🔍 Scanning: {url}")
    
    # 1. Extract Features
    features = extract_features(url)
    if features is None:
        print("❌ Could not extract features from URL.")
        return

    # 2. Convert to DataFrame (Model expects a 2D array/DataFrame)
    # We must ensure columns match exactly what the model was trained on
    feature_df = pd.DataFrame([features])
    
    # Select only the numeric columns used in training
    # (These must match the list in train_model.py)
    required_cols = [
        'url_length', 'domain_length', 'path_length', 'query_length',
        'num_dots', 'num_hyphens', 'num_digits', 'num_special_chars',
        'has_ip', 'is_https', 'has_php', 'has_html', 'has_exe'
    ]
    
    # Filter to ensure order is correct
    X = feature_df[required_cols]

    # 3. Predict
    prediction = model.predict(X)[0]
    probability = model.predict_proba(X)[0][1] # Probability of being class 1 (Malicious)

    # 4. Result
    if prediction == 1:
        print(f"🚫 DANGER: This looks like a SCAM/MALWARE URL! (Confidence: {probability:.1%})")
    else:
        print(f"✅ SAFE: This looks like a normal URL. (Confidence: {1-probability:.1%})")

if __name__ == "__main__":
    # Allow running via command line: python predict_url.py "http://google.com"
    if len(sys.argv) > 1:
        user_url = sys.argv[1]
        predict(user_url)
    else:
        # Default test if no argument provided
        print("--- Test 1 (Safe) ---")
        predict("https://www.google.com")
        print("\n--- Test 2 (Malicious) ---")
        predict("http://192.168.1.55/bin.sh")