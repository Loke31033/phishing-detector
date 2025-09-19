import pandas as pd

print("✅ Pandas imported successfully")

# Replace with your dataset path if you already downloaded one
dataset_path = "data/sample.csv"

try:
    df = pd.read_csv(dataset_path)
    print("Dataset loaded successfully ✅")
    print(df.head())
except FileNotFoundError:
    print("⚠️ No dataset found yet. Create data/sample.csv to test loading.")

