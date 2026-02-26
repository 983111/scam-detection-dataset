import pandas as pd
import joblib
import os
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

# Configuration
DATA_PATH  = "../data/processed/dataset_balanced.csv"
MODEL_PATH = "../models/scam_detector.pkl"

FEATURE_COLS = [
    "url_length", "domain_length", "path_length", "query_length",
    "num_dots", "num_hyphens", "num_digits", "num_special_chars",
    "has_ip", "is_https", "has_php", "has_html", "has_exe",
]


def train():
    print("🚀 Loading dataset …")
    try:
        df = pd.read_csv(DATA_PATH)
    except FileNotFoundError:
        print("❌ Dataset not found. Run add_benign_data.py first.")
        return

    print(f"   Total rows : {len(df):,}")
    print(f"   Malicious  : {(df['label'] == 1).sum():,}")
    print(f"   Benign     : {(df['label'] == 0).sum():,}")

    # Validate columns
    missing = [c for c in FEATURE_COLS if c not in df.columns]
    if missing:
        print(f"⚠️  Missing columns: {missing}")
        return

    X = df[FEATURE_COLS]
    y = df["label"]

    # Train / test split — 80 / 20
    print("📊 Splitting data …")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"   Train: {len(X_train):,}   Test: {len(X_test):,}")

    # Train
    # n_jobs=-1  → use all CPU cores (important for 1-lakh dataset)
    # n_estimators=200 → more trees = better generalisation on larger data
    print("🧠 Training Random Forest (n_estimators=200, n_jobs=-1) …")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,          # grow full trees
        min_samples_leaf=2,      # slight regularisation
        n_jobs=-1,
        random_state=42,
    )
    model.fit(X_train, y_train)

    # Evaluate
    predictions = model.predict(X_test)
    acc         = accuracy_score(y_test, predictions)

    print("\n" + "=" * 40)
    print(f"🏆  MODEL ACCURACY: {acc:.4%}")
    print("=" * 40)
    print("\nClassification Report:")
    print(classification_report(y_test, predictions, target_names=["Benign (0)", "Malicious (1)"]))

    # Feature importance
    print("📌 Feature Importances:")
    importance = sorted(
        zip(FEATURE_COLS, model.feature_importances_),
        key=lambda x: x[1], reverse=True,
    )
    for feat, score in importance:
        bar = "█" * int(score * 50)
        print(f"   {feat:<22} {score:.4f}  {bar}")

    # Save
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"\n💾 Model saved to {MODEL_PATH}")


if __name__ == "__main__":
    train()