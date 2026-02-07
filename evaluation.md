# Model Evaluation Report

This document provides a detailed analysis of the Scam URL Detection model's performance, metrics, and feature importance.

## 📊 Performance Metrics
The model was evaluated using a 20% test split from a balanced dataset of 28,142 URLs.

| Metric | Score |
| :--- | :--- |
| **Accuracy** | 99.96% |
| **Precision (Malicious)** | 1.00 |
| **Recall (Malicious)** | 1.00 |
| **F1-Score** | 1.00 |

### **Understanding the 99.96% Accuracy**
While 99.96% is exceptionally high, it is a result of the clear structural differences between the two data sources used:
1.  **Malicious Source (URLhaus):** Frequently contains raw IP addresses, non-standard ports, and direct paths to executable files (e.g., `/bin.sh`, `/i`).
2.  **Benign Source (Tranco):** Consists of top-level highly reputable domains (e.g., `google.com`) which rarely use raw IPs or suspicious file paths in their root structure.

## 🛠️ Feature Importance
The Random Forest classifier relies on the following lexical features to make predictions:

1.  **`has_ip`**: Most significant indicator. Malicious URLs in this dataset often use IP addresses instead of registered domain names.
2.  **`url_length`**: Malicious URLs tend to be longer due to complex paths or encoded strings.
3.  **`has_exe` / `has_php`**: The presence of server-side scripts or binary extensions in the path is a high-risk signal for malware distribution.
4.  **`num_special_chars`**: Excessive use of `@`, `?`, and `&` is common in phishing and tracking URLs.

## 📈 Confusion Matrix Summary
Based on the classification report:
* **True Positives (TP):** Scams correctly identified as scams.
* **True Negatives (TN):** Safe sites correctly identified as safe.
* **False Positives (FP):** Safe sites wrongly flagged (Very Low).
* **False Negatives (FN):** Scams that bypassed detection (Very Low).

## ⚠️ Limitations & Real-World Use
* **Targeting Bias:** The model is highly effective against malware distribution points but may require more diverse phishing data to catch sophisticated social engineering "look-alike" domains.
* **Inference Confidence:** In local testing, highly reputable root domains like `google.com` returned a 52% safe confidence, while specific malicious paths returned 100% scam confidence. This suggests the model is most certain when identifying clear malicious patterns rather than certifying safety.

## 🔄 Retraining Strategy
Because the landscape of malicious URLs changes daily, this model should be retrained weekly using the `src/download_urlhaus.py` and `src/train_model.py` scripts to capture new attack patterns.
