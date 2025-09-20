# src/pipeline/extract_whois_only.py
import os, sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import pandas as pd
from src.features.whois_features import whois_features_from_url

INPUT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data", "sample.csv"))
OUT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data", "processed", "features_whois.csv"))

df = pd.read_csv(INPUT)
rows = []
for _, row in df.iterrows():
    url = row["url"]
    whois_feats = whois_features_from_url(url)
    out = {"url": url, "label": row["label"]}
    out.update(whois_feats)
    rows.append(out)

pd.DataFrame(rows).to_csv(OUT, index=False)
print("Saved:", OUT)
