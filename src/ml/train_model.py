import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score
import joblib
from pathlib import Path

# Paths
processed_csv = Path(__file__).resolve().parents[2] / "dataset/processed/processed_urls.csv"
model_path = Path(__file__).resolve().parents[2] / "models/rf_phishing_model.pkl"

# Create models folder
model_path.parent.mkdir(parents=True, exist_ok=True)

# Load dataset
df = pd.read_csv(processed_csv)

# Features and labels
X = df[['length', 'num_dots', 'has_at', 'https', 'num_hyphen', 'domain_length']]
y = df['label'].map({'phishing':1, 'safe':0})  # Encode labels

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train Random Forest
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# Evaluate
y_pred = clf.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print("Precision:", precision_score(y_test, y_pred))
print("Recall:", recall_score(y_test, y_pred))

# Save model
joblib.dump(clf, model_path)
print(f"✅ Model saved to {model_path}")
