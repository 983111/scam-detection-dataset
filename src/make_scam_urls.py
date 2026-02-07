import pandas as pd
import re
import os
from urllib.parse import urlparse
import tldextract

# Configuration
INPUT_FILE = "../data/raw/urlhaus.csv"
OUTPUT_FILE = "../data/processed/scam_urls_labeled.csv"

def extract_features(url):
    """
    Extracts lexical features from a URL string for ML modeling.
    Returns a dictionary of features.
    """
    try:
        parsed = urlparse(url)
        ext = tldextract.extract(url)
        
        features = {
            # Structural Features
            'url_length': len(url),
            'domain_length': len(ext.domain),
            'path_length': len(parsed.path),
            'query_length': len(parsed.query),
            
            # Character Counts
            'num_dots': url.count('.'),
            'num_hyphens': url.count('-'),
            'num_digits': sum(c.isdigit() for c in url),
            'num_special_chars': len(re.findall(r'[@?&=%_]', url)),
            
            # Binary/Boolean Features
            'has_ip': 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0,
            'is_https': 1 if parsed.scheme == 'https' else 0,
            'has_php': 1 if '.php' in parsed.path else 0,
            'has_html': 1 if '.html' in parsed.path else 0,
            'has_exe': 1 if '.exe' in parsed.path else 0,
        }
        return features
    except Exception:
        return None

def process_data():
    print("🔄 Loading raw data...")
    
    # URLhaus CSVs often have comments at the top; skiprows=8 usually skips the header info
    # We try to detect the header row automatically or default to 8
    try:
        df = pd.read_csv(INPUT_FILE, skiprows=8, on_bad_lines='skip')
    except FileNotFoundError:
        print(f"❌ Input file not found at {INPUT_FILE}. Please run download_urlhaus.py first.")
        return

    # Basic cleaning
    print(f"   Raw rows: {len(df)}")
    df.columns = [c.strip().replace('"', '') for c in df.columns] # Clean column names
    
    if 'url' not in df.columns:
        print("❌ Error: 'url' column not found in CSV.")
        print(f"   Found columns: {df.columns}")
        return

    # Filter for valid URLs only
    df = df.dropna(subset=['url'])
    df = df.drop_duplicates(subset=['url'])
    
    # 1. Labeling
    # Since this source is purely malicious, we label everything as 1
    df['label'] = 1 
    
    # 2. Feature Extraction
    print("⚙️ Extracting features (this may take a moment)...")
    feature_data = df['url'].apply(lambda x: extract_features(x))
    feature_df = pd.DataFrame(feature_data.tolist())
    
    # Combine original data with features
    final_df = pd.concat([df[['url', 'label', 'threat', 'tags']], feature_df], axis=1)
    
    # Remove rows where feature extraction failed
    final_df = final_df.dropna()

    # Save
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    final_df.to_csv(OUTPUT_FILE, index=False)
    print(f"✅ Processed dataset saved to {OUTPUT_FILE}")
    print(f"   Final shape: {final_df.shape}")
    print("\n   Sample Data:")
    print(final_df[['url', 'label', 'url_length', 'has_ip']].head())

if __name__ == "__main__":
    process_data()