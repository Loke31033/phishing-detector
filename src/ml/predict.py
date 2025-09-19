import re
import joblib
from urllib.parse import urlparse
from pathlib import Path
import sys

# Path to trained model
model_path = Path(__file__).resolve().parents[2] / "models/rf_phishing_model.pkl"
clf = joblib.load(model_path)

# Extract features from URL
def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc

    features = {
        "length": len(url),
        "num_dots": url.count("."),
        "has_at": 1 if "@" in url else 0,
        "https": 1 if parsed.scheme == "https" else 0,
        "num_hyphen": url.count("-"),
        "domain_length": len(domain),
    }
    return [features[f] for f in ["length", "num_dots", "has_at", "https", "num_hyphen", "domain_length"]]

# CLI usage
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 src/ml/predict.py <URL>")
        sys.exit(1)

    url = sys.argv[1]
    X = [extract_features(url)]
    prediction = clf.predict(X)[0]

    if prediction == 1:
        print(f"⚠️ Phishing detected: {url}")
    else:
        print(f"✅ Safe URL: {url}")
