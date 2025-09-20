# tests/test_whois.py
from src.features.whois_features import whois_features_from_url

def run():
    samples = [
        "https://www.google.com",
        "http://login-paypal.com@malicious.com",
        "http://example.com"
    ]
    for s in samples:
        print(s, "->", whois_features_from_url(s))

if __name__ == "__main__":
    run()

