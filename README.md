Markdown
#  Stremini AI - Scam URL Detector

An AI-powered API that detects malicious URLs (phishing, malware, scam sites) in real-time. 
Built with **Python**, **Scikit-Learn (Random Forest)**, and **FastAPI**.

## 📊 Dataset Overview
This project uses a custom "High ROI" balanced dataset of **~28,000 URLs**:
* **Malicious (50%):** Sourced from [URLhaus](https://urlhaus.abuse.ch/) (active malware distribution sites).
* **Benign (50%):** Sourced from the [Tranco Top 1M](https://tranco-list.eu/) (globally trusted domains).
* **Features:** The model analyzes lexical features like URL length, IP address usage, special characters, and path complexity.

## 🚀 Project Structure
```text
scam-url-dataset/
├── README.md                  # Project Documentation
├── requirements.txt           # Dependencies
├── data/
│   ├── raw/                   # Raw CSV downloads (urlhaus.csv)
│   └── processed/             # Cleaned & labeled datasets
├── models/
│   └── scam_detector.pkl      # Trained Random Forest Model
└── src/
    ├── download_urlhaus.py    # Downloads fresh malware data
    ├── make_scam_urls.py      # Cleans malicious data & extracts features
    ├── add_benign_data.py     # Downloads safe sites & balances dataset
    ├── train_model.py         # Trains the ML model
    ├── predict_url.py         # CLI tool to test a single URL
    └── api.py                 # FastAPI server for real-time scanning
🛠️ Installation
Clone the repository:

Bash
git clone [https://github.com/yourusername/stremini-scam-detector.git](https://github.com/yourusername/stremini-scam-detector.git)
cd stremini-scam-detector
Install dependencies:

Bash
pip install -r requirements.txt
⚡ How to Run (Step-by-Step)
Phase 1: Data Preparation
You must generate the dataset before training. Run these scripts in order:

Bash
cd src
# 1. Download fresh malware data
python download_urlhaus.py

# 2. Process malware data
python make_scam_urls.py

# 3. Add safe sites to balance the dataset
python add_benign_data.py
Phase 2: Training the AI
Train the Random Forest classifier. This will create scam_detector.pkl.

Bash
python train_model.py
Expected Accuracy: >99%

Phase 3: Start the API Server
Launch the FastAPI server to accept real-time requests.

Bash
uvicorn api:app --reload
Server will start at: http://127.0.0.1:8000

🔌 API Usage
Endpoint: /scan (POST)
Send a JSON request with the URL you want to check.

Request (cURL):

Bash
curl -X POST "[http://127.0.0.1:8000/scan](http://127.0.0.1:8000/scan)" \
     -H "Content-Type: application/json" \
     -d '{"url": "[http://suspicious-site.com/login.php](http://suspicious-site.com/login.php)"}'
Response:

JSON
{
  "url": "[http://suspicious-site.com/login.php](http://suspicious-site.com/login.php)",
  "is_scam": true,
  "confidence_score": 0.9850,
  "risk_level": "CRITICAL"
}
⚠️ Bias & Limitations
Source Bias: Malicious data is heavily weighted toward malware distribution (URLhaus) rather than social engineering phishing.

Temporal Bias: Threat intelligence expires quickly. The model should be retrained weekly with fresh data.

Benign Bias: Safe sites are drawn from "Top 1M" domains. Obscure but safe personal blogs might be misclassified if they use unusual URL structures (e.g., IP addresses).

🔮 Future Roadmap
[ ] Add "Whois" domain age features (new domains are riskier).

[ ] Integrate Google Safe Browsing API as a secondary check.

[ ] Deploy to Cloudflare Workers for edge latency.
