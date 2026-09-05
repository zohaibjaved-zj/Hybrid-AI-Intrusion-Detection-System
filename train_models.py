import warnings
warnings.filterwarnings("ignore", message="`sklearn.utils.parallel.delayed`")

# Rest of your existing code...
import pandas as pd
import numpy as np
# ... continue as before

# train_models.py - Robust training for CICIDS2017

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.decomposition import PCA
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import os

os.makedirs("models", exist_ok=True)

print("Loading merged_dataset.csv...")
df = pd.read_csv("merged_dataset.csv", low_memory=False)

# Critical: Strip column names (removes hidden spaces)
df.columns = df.columns.str.strip()

print(f"Columns after cleaning: {len(df.columns)}")
print("Sample columns:", list(df.columns[:10]))

# Replace inf and NaN
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.fillna(0, inplace=True)

# Define the correct feature names (exact match from CICIDS2017)
features = [
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Fwd Packet Length Mean',
    'Protocol',
    'Source Port',
    'Destination Port',
    'Flow Packets/s',
    'Fwd Packet Length Max'
]

# Find available features (some might be missing in certain files)
available_features = [f for f in features if f in df.columns]
missing = [f for f in features if f not in df.columns]

if missing:
    print(f"Warning: Missing features {missing} — will use only available ones.")

print(f"Using {len(available_features)} features for training.")

X = df[available_features]

# Label column (should now exist and be clean)
if 'Label' not in df.columns:
    raise ValueError("Label column not found! Check dataset.")
y = df['Label'].str.strip()

# Encode labels
le = LabelEncoder()
y_encoded = le.fit_transform(y)
print(f"Classes: {le.classes_}")

# Preprocessing pipeline
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

pca = PCA(n_components=min(15, len(available_features)))  # More components for better accuracy
X_pca = pca.fit_transform(X_scaled)

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X_pca, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded)

# Random Forest for known attacks
print("\nTraining Random Forest (this may take 5-10 minutes with 2.8M rows)...")
rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1, class_weight='balanced')
rf.fit(X_train, y_train)

# Isolation Forest on BENIGN only for zero-day detection
print("Training Isolation Forest on BENIGN traffic...")
benign_mask = (y == 'BENIGN')
X_benign_pca = X_pca[benign_mask]
isof = IsolationForest(contamination=0.01, random_state=42, n_jobs=-1)
isof.fit(X_benign_pca)

# Evaluation
print("\n=== Random Forest Performance ===")
y_pred = rf.predict(X_test)
print(classification_report(y_test, y_pred, target_names=le.classes_, zero_division=0))

# Save pipeline
joblib.dump({
    'rf': rf,
    'isof': isof,
    'scaler': scaler,
    'pca': pca,
    'le': le,
    'features': available_features
}, "models/ids_pipeline.joblib")

print("\n🎉 Training complete! Models saved to models/ids_pipeline.joblib")
print("Next: Run the dashboard with admin rights → python app.py")