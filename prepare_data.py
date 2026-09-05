# prepare_data.py - Robust dataset preparation (handles CICIDS2017 column quirks)

import pandas as pd
import os
import numpy as np

# Create folders
os.makedirs("data", exist_ok=True)
os.makedirs("models", exist_ok=True)

print("Generating synthetic DDoS attack features (in-memory)...")
# In-memory synthetic DDoS samples (no PCAP file issues)
synthetic_data = []
for i in range(1000):
    synthetic_data.append({
        'Flow Duration': np.random.randint(500, 5000),
        'Total Fwd Packets': 1,          # Note: CICIDS uses "Total Fwd Packets" (with space)
        'Total Backward Packets': 0,
        ' Fwd Packet Length Mean': np.random.randint(40, 60),
        ' Protocol': 6,
        ' Source Port': np.random.randint(1024, 65535),
        ' Destination Port': 80,
        'Flow Packets/s': np.random.uniform(500, 2000),
        ' Fwd Packet Length Max': 60
    })

syn_df = pd.DataFrame(synthetic_data)
syn_df[' Label'] = 'DDoS'  # Use exact column name with space
print(f"Generated {len(syn_df)} synthetic DDoS samples")

# Load CICIDS2017 CSVs
cic_files = [f for f in os.listdir("data") if f.endswith(".csv")]
if not cic_files:
    print("\nWarning: No CSV files in data/ folder. Using only synthetic data.")
    df = syn_df
else:
    print(f"Loading {len(cic_files)} CSV file(s)...")
    dfs = []
    for file in cic_files:
        print(f"   Loading {file}...")
        temp_df = pd.read_csv(os.path.join("data", file), low_memory=False)
        # Fix common issues
        temp_df.columns = temp_df.columns.str.strip()  # Remove leading/trailing spaces in column names
        if 'Label' not in temp_df.columns:
            print(f"   Warning: No 'Label' column in {file}. Skipping or using BENIGN.")
            temp_df['Label'] = 'BENIGN'
        dfs.append(temp_df)

    cic_df = pd.concat(dfs, ignore_index=True)

    # Clean label column (remove extra spaces in values)
    cic_df['Label'] = cic_df['Label'].str.strip()

    # Merge with synthetic
    df = pd.concat([cic_df, syn_df], ignore_index=True, sort=False)  # sort=False to avoid warnings
    print(f"Final merged dataset: {df.shape[0]} rows, {df.shape[1]} columns")

# Final cleanup: Replace inf/nan
df.replace([np.inf, -np.inf], np.nan, inplace=True)
