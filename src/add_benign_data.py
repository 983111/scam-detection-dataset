import pandas as pd
import requests
import zipfile
import io
import os
# We import the feature extractor you already built to ensure consistency
from make_scam_urls import extract_features

# Configuration
BENIGN_SOURCE_URL = "https://tranco-list.eu/top-1m.csv.zip"
MALICIOUS_DATA_PATH = "../data/processed/scam_urls_labeled.csv"
FINAL_OUTPUT_PATH = "../data/processed/dataset_balanced.csv"

def fetch_benign_data():
    print(f"📥 Downloading Benign (Safe) domains from {BENIGN_SOURCE_URL}...")
    try:
        r = requests.get(BENIGN_SOURCE_URL)
        r.raise_for_status()
        
        # Unzip in memory
        with zipfile.ZipFile(io.BytesIO(r.content)) as z:
            # Tranco zip usually contains 'top-1m.csv'
            csv_name = z.namelist()[0]
            with z.open(csv_name) as f:
                # Read only top 15,000 to match your malicious count (approx 13k)
                df = pd.read_csv(f, header=None, names=['rank', 'url'], nrows=15000)
    except Exception as e:
        print(f"❌ Error downloading benign data: {e}")
        return None

    print(f"✅ Downloaded top {len(df)} safe domains.")
    
    # Process Benign Data
    # 1. Add 'http://' because raw domains like 'google.com' don't have schemes, 
    #    but your malicious data does.
    df['url'] = "http://" + df['url']
    
    # 2. Label as 0 (Safe)
    df['label'] = 0
    
    return df

def main():
    # 1. Load existing malicious data
    if not os.path.exists(MALICIOUS_DATA_PATH):
        print("❌ Malicious dataset not found. Run make_scam_urls.py first.")
        return
    
    malicious_df = pd.read_csv(MALICIOUS_DATA_PATH)
    print(f"🔄 Loaded {len(malicious_df)} malicious rows.")

    # 2. Fetch and prep benign data
    benign_df = fetch_benign_data()
    if benign_df is None: return

    # 3. Extract features for benign data
    print("⚙️ Extracting features for benign URLs (this will take a minute)...")
    feature_data = benign_df['url'].apply(lambda x: extract_features(x))
    feature_df = pd.DataFrame(feature_data.tolist())
    
    # Combine url + label + features
    benign_processed = pd.concat([benign_df[['url', 'label']], feature_df], axis=1)
    
    # 4. Merge and Shuffle
    print("🔄 Merging datasets...")
    # Align columns (malicious_df might have extra columns like 'threat', 'tags' which we fill with NaN for benign)
    full_df = pd.concat([malicious_df, benign_processed], ignore_index=True)
    
    # Shuffle the dataset so 0s and 1s are mixed
    full_df = full_df.sample(frac=1, random_state=42).reset_index(drop=True)

    # 5. Save Final
    full_df.to_csv(FINAL_OUTPUT_PATH, index=False)
    print(f"🎉 SUCCESS! Final Balanced Dataset saved to {FINAL_OUTPUT_PATH}")
    print(f"   Total Rows: {len(full_df)}")
    print(f"   Malicious (1): {len(full_df[full_df['label']==1])}")
    print(f"   Benign    (0): {len(full_df[full_df['label']==0])}")

if __name__ == "__main__":
    main()