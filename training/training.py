import os
import glob
import time
import joblib
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import LabelEncoder

# Configuration
DATA_DIR = r"/mnt/c/Users/smayan/Desktop/threat-hunter"
MODEL_OUTPUT = "hgb_model.joblib"

# Features used in scammer5.py (MUST MATCH EXACTLY)
FEATURE_COLUMNS = [
    'Init Fwd Win Bytes', 'Fwd Header Length', 'Fwd Seg Size Min',
    'Fwd Packets Length Total', 'Fwd Packet Length Max', 'Subflow Fwd Bytes',
    'Fwd Packet Length Mean', 'Bwd Packet Length Mean', 'Fwd IAT Total',
    'Fwd Packets/s', 'Flow IAT Mean', 'Bwd Packet Length Std',
    'Flow IAT Min', 'Fwd IAT Min', 'Flow Packets/s', 'Flow IAT Max',
    'Flow Duration', 'Avg Fwd Segment Size', 'Fwd IAT Max', 'Avg Bwd Segment Size'
]

def load_data(data_dir):
    print(f"[*] Searching for .parquet files in {data_dir}...")
    parquet_files = glob.glob(os.path.join(data_dir, "*.parquet"))
    
    if not parquet_files:
        raise FileNotFoundError(f"No .parquet files found in {data_dir}")
        
    print(f"[*] Found {len(parquet_files)} files. Loading...")
    
    dfs = []
    for f in parquet_files:
        try:
            df = pd.read_parquet(f)
            dfs.append(df)
            print(f"    - Loaded {os.path.basename(f)} ({len(df)} rows)")
        except Exception as e:
            print(f"    [!] Failed to load {f}: {e}")
            
    if not dfs:
        raise RuntimeError("No data loaded.")
        
    full_df = pd.concat(dfs, ignore_index=True)
    print(f"[*] Total records: {len(full_df)}")
    return full_df

def preprocess_data(df):
    print("[*] Preprocessing data...")
    
    # Check for missing columns
    missing_cols = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing_cols:
        print(f"[!] Warning: Missing columns in data: {missing_cols}")
        # Add missing columns with 0s
        for c in missing_cols:
            df[c] = 0
            
    # Select features and target
    X = df[FEATURE_COLUMNS].copy()
    
    # Handle infinite/NaN values
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0, inplace=True)
    
    # Target processing
    if 'Label' in df.columns:
        y = df['Label']
    elif 'label' in df.columns:
        y = df['label']
    else:
        raise ValueError("Target column 'Label' or 'label' not found in dataset.")
        
    return X, y

def train_model():
    # 1. Load Data
    df = load_data(DATA_DIR)
    
    # 2. Preprocess
    X, y = preprocess_data(df)
    
    # Encode labels
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)
    print(f"[*] Classes: {le.classes_}")
    
    # 3. Split
    print("[*] Splitting data...")
    X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.2, random_state=42)
    
    # 4. Train
    print("[*] Training HistGradientBoostingClassifier...")
    # Using parameters compatible with modern sklearn
    clf = HistGradientBoostingClassifier(
        learning_rate=0.1,
        max_iter=100,
        max_leaf_nodes=31,
        random_state=42,
        class_weight='balanced'
    )
    
    t0 = time.time()
    clf.fit(X_train, y_train)
    print(f"[*] Training completed in {time.time() - t0:.2f}s")
    
    # 5. Evaluate
    preds = clf.predict(X_test)
    acc = accuracy_score(y_test, preds)
    print(f"[*] Accuracy: {acc:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, preds, target_names=le.classes_.astype(str)))
    
    # 6. Save Model
    # We need to save the model AND the label encoder to decode predictions later if needed
    # But scammer5.py expects just the model object. 
    # Ideally, we should wrap them, but for compatibility with current scammer5.py, 
    # we will just save the classifier. 
    # NOTE: scammer5.py expects the model to return the STRING label directly or we need to decode it.
    # The current scammer5.py code: prediction = ml_model.predict(...)[0]
    # If we train on encoded integers, predict() returns integers.
    # We need to ensure the model returns string labels OR we modify scammer5.py.
    # 
    # BETTER APPROACH: Use a pipeline or just train on string labels if HGB supports it (it doesn't natively for strings in older versions, but recent ones might handle categorical).
    # Safest bet: Train on strings directly? HGB requires numerical input for X, but y can be anything? 
    # Actually, sklearn classifiers usually handle string y automatically but return string y.
    # Let's try fitting with original y (strings) directly. HGB supports it.
    
    print("[*] Retraining with string labels for compatibility...")
    clf.fit(X_train, y_train) # Re-fitting with integer y? No wait.
    
    # Let's just fit with the original string labels 'y' (split appropriately)
    X_train_str, X_test_str, y_train_str, y_test_str = train_test_split(X, y, test_size=0.2, random_state=42)
    clf.fit(X_train_str, y_train_str)
    
    print(f"[*] Saving model to {MODEL_OUTPUT}...")
    joblib.dump(clf, MODEL_OUTPUT, compress=3)
    print("[*] Done.")

if __name__ == "__main__":
    try:
        train_model()
    except Exception as e:
        print(f"[!] Error: {e}")
