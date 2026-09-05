# merge_csvs.py - Simple merge of all CSVs in data/ folder

import pandas as pd
import os

# Folder with your CICIDS2017 CSV files
data_folder = "data"

# Get all CSV files
csv_files = [f for f in os.listdir(data_folder) if f.endswith(".csv")]
print(f"Found {len(csv_files)} CSV files: {csv_files}")

# Read and combine all
dfs = []
for file in csv_files:
    print(f"Loading {file}...")
    path = os.path.join(data_folder, file)
    df = pd.read_csv(path, low_memory=False)
    # Clean column names
    df.columns = df.columns.str.strip()
    # Clean Label column if exists
    if 'Label' in df.columns:
        df['Label'] = df['Label'].str.strip()
    else:
        df['Label'] = 'BENIGN'  # default
    dfs.append(df)

# Merge all
merged_df = pd.concat(dfs, ignore_index=True)

# Clean inf/nan
merged_df.replace([float('inf'), -float('inf')], float('nan'), inplace=True)
merged_df.fillna(0, inplace=True)

# Save
merged_df.to_csv("merged_dataset.csv", index=False)
print(f"\nSuccess! Merged {len(dfs)} files → {merged_df.shape[0]} rows, {merged_df.shape[1]} columns")
print("Saved as merged_dataset.csv")