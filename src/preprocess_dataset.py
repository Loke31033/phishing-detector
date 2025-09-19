import pandas as pd
import re
from pathlib import Path
import urllib.parse as urlparse

# Paths
raw_phish = Path(__file__).resolve().parents[1] / "dataset/raw/phishing_dataset.csv"
raw_safe = Path(__file__).resolve().parents[1] / "dataset/raw/safe_urls.csv"
processed_path = Path(__file__).resolve().parents[1] / "dataset/processed/processed_urls.csv"

# Load datasets
df_phish = pd.read_csv(raw_phish, encoding='latin1', on_bad_lines='skip')
df_safe = pd.read_csv(raw_safe)

# Standardize column names (assume URL in first column, label in second)
df_phish = df_phish.rename(columns={df_phish.columns[0]: 'url'})
df_safe = df_safe.rename(columns={df_safe.columns[0]: 'url'})

# Add labels if not present
if 'label' not in df_phish.columns:
    df_phish['label'] = 'phishing'
if 'label' not in df_safe.columns:
    df_safe['label'] = 'safe'

# Combine datasets
df = pd.concat([df_phish[['url','label']], df_safe[['url','label']]], ignore_index=True)

# Remove duplicates
df.drop_duplicates(subset='url', inplace=True)

# Feature extraction
def extract_features(url):
    features = {}
    features['length'] = len(url)
    features['num_dots'] = url.count('.')
    features['has_at'] = int('@' in url)
    features['https'] = int(url.startswith('https'))
    features['num_hyphen'] = url.count('-')
    # domain length
    parsed = urlparse.urlparse(url)
    features['domain_length'] = len(parsed.netloc)
    return features

feature_df = df['url'].apply(lambda x: pd.Series(extract_features(x)))
final_df = pd.concat([df, feature_df], axis=1)

# Save processed dataset
processed_path.parent.mkdir(parents=True, exist_ok=True)
final_df.to_csv(processed_path, index=False)
print(f"✅ Processed dataset saved to {processed_path}")
print(final_df.head())
