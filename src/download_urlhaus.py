import requests
import os

def download_urlhaus_data():
    # FIXED: Changed 'csv-online' to 'csv_online'
    url = "https://urlhaus.abuse.ch/downloads/csv_online/"
    save_path = "../data/raw/urlhaus.csv"
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    
    print(f"📥 Downloading malicious URL data from {url}...")
    try:
        response = requests.get(url)
        response.raise_for_status()
        
        # Save to file
        with open(save_path, 'wb') as f:
            f.write(response.content)
        
        print(f"✅ Download complete! Saved to {save_path}")
        
    except Exception as e:
        print(f"❌ Error downloading data: {e}")

if __name__ == "__main__":
    download_urlhaus_data()