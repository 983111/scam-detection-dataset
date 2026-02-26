import pandas as pd
import requests
import zipfile
import io
import os
from make_scam_urls import extract_features

# Configuration
BENIGN_SOURCE_URL = "https://tranco-list.eu/top-1m.csv.zip"
MALICIOUS_DATA_PATH = "../data/processed/scam_urls_labeled.csv"
FINAL_OUTPUT_PATH = "../data/processed/dataset_balanced.csv"

# ── TARGET SIZE ──────────────────────────────────────────────────────────────
TARGET_BENIGN   = 50_000   # We want 50 k benign rows
TARGET_MALICIOUS = 50_000  # We cap malicious at 50 k to keep the dataset balanced
# Total dataset: ~1,00,000 URLs
# ─────────────────────────────────────────────────────────────────────────────

def fetch_benign_data(n: int = TARGET_BENIGN) -> pd.DataFrame | None:
    print(f"📥 Downloading Benign (Safe) domains from {BENIGN_SOURCE_URL}...")
    try:
        r = requests.get(BENIGN_SOURCE_URL, timeout=120)
        r.raise_for_status()

        with zipfile.ZipFile(io.BytesIO(r.content)) as z:
            csv_name = z.namelist()[0]
            with z.open(csv_name) as f:
                df = pd.read_csv(f, header=None, names=["rank", "url"], nrows=n)
    except Exception as e:
        print(f"❌ Error downloading benign data: {e}")
        return None

    print(f"✅ Downloaded top {len(df)} safe domains.")

    df["url"]   = "http://" + df["url"]
    df["label"] = 0
    return df


def main():
    # 1. Load existing malicious data
    if not os.path.exists(MALICIOUS_DATA_PATH):
        print("❌ Malicious dataset not found. Run make_scam_urls.py first.")
        return

    malicious_df = pd.read_csv(MALICIOUS_DATA_PATH)
    print(f"🔄 Loaded {len(malicious_df)} malicious rows.")

    # Cap malicious rows at TARGET_MALICIOUS so both classes stay balanced
    if len(malicious_df) > TARGET_MALICIOUS:
        malicious_df = malicious_df.sample(n=TARGET_MALICIOUS, random_state=42)
        print(f"   ✂️  Capped to {TARGET_MALICIOUS} malicious rows for balance.")
    elif len(malicious_df) < TARGET_MALICIOUS:
        print(
            f"   ⚠️  Only {len(malicious_df)} malicious rows available "
            f"(wanted {TARGET_MALICIOUS}). Consider refreshing URLhaus data."
        )

    actual_benign_target = len(malicious_df)  # mirror exactly
    print(f"   🎯 Will fetch {actual_benign_target} benign rows to match.")

    # 2. Fetch and prep benign data
    benign_df = fetch_benign_data(n=actual_benign_target)
    if benign_df is None:
        return

    # 3. Extract features for benign URLs
    print("⚙️  Extracting features for benign URLs (this will take a few minutes)...")
    feature_data = benign_df["url"].apply(extract_features)
    feature_df   = pd.DataFrame(feature_data.tolist())

    benign_processed = pd.concat([benign_df[["url", "label"]], feature_df], axis=1)

    # 4. Merge & Shuffle
    print("🔄 Merging datasets...")
    full_df = pd.concat([malicious_df, benign_processed], ignore_index=True)
    full_df = full_df.sample(frac=1, random_state=42).reset_index(drop=True)

    # 5. Save
    os.makedirs(os.path.dirname(FINAL_OUTPUT_PATH), exist_ok=True)
    full_df.to_csv(FINAL_OUTPUT_PATH, index=False)

    print(f"\n🎉 SUCCESS! Final Balanced Dataset saved to {FINAL_OUTPUT_PATH}")
    print(f"   Total Rows : {len(full_df):,}")
    print(f"   Malicious (1): {len(full_df[full_df['label'] == 1]):,}")
    print(f"   Benign    (0): {len(full_df[full_df['label'] == 0]):,}")


if __name__ == "__main__":
    main()