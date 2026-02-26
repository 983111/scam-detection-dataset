import csv
import os
import re
import pandas as pd
from urllib.parse import urlparse
import tldextract

# Configuration
INPUT_FILE  = "../data/raw/urlhaus.csv"
OUTPUT_FILE = "../data/processed/scam_urls_labeled.csv"

# Cap for malicious rows (half of 1-lakh target)
MALICIOUS_CAP = 50_000


def extract_features(url: str):
    """
    Extracts lexical features from a URL string for ML modelling.
    Returns a dictionary of features, or None on parse failure.
    """
    try:
        parsed = urlparse(url)
        ext    = tldextract.extract(url)

        return {
            "url_length"       : len(url),
            "domain_length"    : len(ext.domain),
            "path_length"      : len(parsed.path),
            "query_length"     : len(parsed.query),
            "num_dots"         : url.count("."),
            "num_hyphens"      : url.count("-"),
            "num_digits"       : sum(c.isdigit() for c in url),
            "num_special_chars": len(re.findall(r"[@?&=%_]", url)),
            "has_ip"   : 1 if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url) else 0,
            "is_https" : 1 if parsed.scheme == "https" else 0,
            "has_php"  : 1 if ".php"  in parsed.path else 0,
            "has_html" : 1 if ".html" in parsed.path else 0,
            "has_exe"  : 1 if ".exe"  in parsed.path else 0,
        }
    except Exception:
        return None


def load_urlhaus_csv(path: str) -> pd.DataFrame:
    """
    Manually parse the URLhaus CSV using Python's csv module.
    This avoids pandas buffer-overflow and UnicodeDecodeError issues
    caused by malformed rows and non-UTF-8 bytes in the full dump.
    """
    # Increase the field-size limit — some URL fields are very long
    csv.field_size_limit(10 * 1024 * 1024)  # 10 MB per field

    # URLhaus column order (both online feed and full historical dump)
    URLHAUS_COLS = ["id", "dateadded", "url", "url_status", "last_online",
                    "threat", "tags", "urlhaus_link", "reporter"]

    rows   = []
    header = None

    with open(path, "r", encoding="latin-1", errors="replace") as fh:
        reader = csv.reader(fh)
        for raw_row in reader:
            # Skip comment/blank lines
            if not raw_row or raw_row[0].startswith("#"):
                continue

            # Detect whether the first data row IS a header or actual data.
            # A header row will have a non-numeric first field (e.g. "id").
            # A data row will have a numeric ID like "3786164".
            if header is None:
                first_field = raw_row[0].strip().strip('"')
                if first_field.lstrip("-").isdigit():
                    # No header in file — inject the known column names
                    header = URLHAUS_COLS
                else:
                    # File has a real header row — use it
                    header = [c.strip().strip('"') for c in raw_row]
                    continue   # don't add the header row to data

            # Pad or truncate to match header length
            row = raw_row[:len(header)]
            while len(row) < len(header):
                row.append("")
            rows.append(row)

    if not header:
        raise ValueError("Could not find header row in URLhaus CSV.")

    return pd.DataFrame(rows, columns=header)


def process_data():
    print("🔄 Loading raw URLhaus data …")

    if not os.path.exists(INPUT_FILE):
        print(f"❌ Input file not found at {INPUT_FILE}. Run download_urlhaus.py first.")
        return

    df = load_urlhaus_csv(INPUT_FILE)
    print(f"   Raw rows: {len(df):,}")

    if "url" not in df.columns:
        print("❌ 'url' column not found.")
        print(f"   Found columns: {list(df.columns)}")
        return

    # Basic cleaning
    df = df[df["url"].str.strip() != ""]
    df = df.dropna(subset=["url"]).drop_duplicates(subset=["url"])
    print(f"   After dedup: {len(df):,} rows")

    # Cap at MALICIOUS_CAP
    if len(df) > MALICIOUS_CAP:
        df = df.sample(n=MALICIOUS_CAP, random_state=42)
        print(f"   ✂️  Sampled down to {MALICIOUS_CAP:,} rows.")

    df["label"] = 1

    # Feature extraction in chunks
    print(f"⚙️  Extracting features for {len(df):,} URLs …")
    CHUNK = 5_000
    parts = []
    for start in range(0, len(df), CHUNK):
        chunk = df.iloc[start : start + CHUNK]
        feat  = chunk["url"].apply(extract_features)
        parts.append(pd.DataFrame(feat.tolist()))
        print(f"   … {min(start + CHUNK, len(df)):,} / {len(df):,}", end="\r")
    print()

    feature_df = pd.concat(parts, ignore_index=True)

    # Only keep columns that actually exist
    meta_cols = ["url", "label"]
    for col in ["threat", "tags"]:
        if col in df.columns:
            meta_cols.append(col)

    final_df = pd.concat(
        [df[meta_cols].reset_index(drop=True), feature_df],
        axis=1,
    ).dropna()

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    final_df.to_csv(OUTPUT_FILE, index=False)

    print(f"✅ Saved to {OUTPUT_FILE}")
    print(f"   Shape: {final_df.shape}")
    print("\n   Sample:")
    print(final_df[["url", "label", "url_length", "has_ip"]].head())


if __name__ == "__main__":
    process_data()