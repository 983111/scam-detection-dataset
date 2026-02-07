import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# Configuration
DATA_PATH = "../data/processed/dataset_balanced.csv"
MODEL_PATH = "../models/scam_detector.pkl"

def train():
    print("🚀 Loading dataset...")
    try:
        df = pd.read_csv(DATA_PATH)
    except FileNotFoundError:
        print("❌ Dataset not found. Please run add_benign_data.py first.")
        return

    # 1. Select Features
    # We only want the numeric columns we calculated, NOT the raw URL string
    feature_cols = [
        'url_length', 'domain_length', 'path_length', 'query_length',
        'num_dots', 'num_hyphens', 'num_digits', 'num_special_chars',
        'has_ip', 'is_https', 'has_php', 'has_html', 'has_exe'
    ]
    
    # Check if all columns exist
    missing_cols = [c for c in feature_cols if c not in df.columns]
    if missing_cols:
        print(f"⚠️ Warning: Missing columns {missing_cols}. logical error in feature extraction?")
        return

    X = df[feature_cols]
    y = df['label']

    # 2. Split Data (80% Train, 20% Test)
    print(f"📊 Splitting data: {len(df)} rows...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # 3. Train Model
    print("🧠 Training Random Forest Model (this may take a moment)...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # 4. Evaluate
    print("📝 Evaluating...")
    predictions = model.predict(X_test)
    acc = accuracy_score(y_test, predictions)
    
    print("\n" + "="*30)
    print(f"🏆 MODEL ACCURACY: {acc:.2%}")
    print("="*30)
    print("\nClassification Report:")
    print(classification_report(y_test, predictions, target_names=['Benign (0)', 'Malicious (1)']))

    # 5. Save Model
    import os
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"💾 Model saved to {MODEL_PATH}")

if __name__ == "__main__":
    train()