from flask import Flask, request, jsonify
import joblib
from urllib.parse import urlparse
from pathlib import Path

app = Flask(__name__)

# Load model
model_path = Path(__file__).resolve().parents[1] / "models/rf_phishing_model.pkl"
clf = joblib.load(model_path)

def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    return [len(url),
            url.count("."),
            1 if "@" in url else 0,
            1 if parsed.scheme == "https" else 0,
            url.count("-"),
            len(domain)]

@app.route("/")
def home():
    return jsonify({"message": "Phishing Detector API is running 🚀"})

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "Please provide a URL"}), 400

    url = data["url"]
    X = [extract_features(url)]
    prediction = clf.predict(X)[0]
    result = "phishing" if prediction == 1 else "safe"

    return jsonify({"url": url, "prediction": result})

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
