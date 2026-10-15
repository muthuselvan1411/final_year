#!/usr/bin/env python3
"""
Inspect downloaded MLRan feature tables and metadata.
Prints shape, column names, head, and summary statistics.
"""

import json
from pathlib import Path
import pandas as pd

raw_dir = Path("data/raw/mlran")

print("=" * 60)
print("Inspecting MLRan Downloaded Files")
print("=" * 60)

# 1. Labels
labels_df = pd.read_csv(raw_dir / "MLRan_labels.csv")
print(f"MLRan_labels.csv shape: {labels_df.shape}")
print(f"Columns: {labels_df.columns.tolist()[:10]}")
print("Label distribution:\n", labels_df.iloc[:, -1].value_counts())
print("\nFirst 3 rows:\n", labels_df.head(3))

# 2. Train features
X_train = pd.read_csv(raw_dir / "MLRan_X_train_RFE.csv")
print(f"\nMLRan_X_train_RFE.csv shape: {X_train.shape}")
print(f"Features count: {X_train.shape[1]}")
print(f"Sample columns: {X_train.columns.tolist()[:10]}")

# 3. Test features
X_test = pd.read_csv(raw_dir / "MLRan_X_test_RFE.csv")
print(f"\nMLRan_X_test_RFE.csv shape: {X_test.shape}")

# 4. Metadata
meta_df = pd.read_csv(raw_dir / "mlran_dataset_metadata.csv")
print(f"\nmlran_dataset_metadata.csv shape: {meta_df.shape}")
print(f"Metadata columns: {meta_df.columns.tolist()[:15]}")
print("\nSample metadata head:\n", meta_df.head(2))

# 5. Type sample IDs
train_ids = pd.read_csv(raw_dir / "type_train_sampleids.csv")
test_ids = pd.read_csv(raw_dir / "type_test_sampleids.csv")
print(f"\ntype_train_sampleids.csv shape: {train_ids.shape}, columns: {train_ids.columns.tolist()}")
print(f"type_test_sampleids.csv shape: {test_ids.shape}, columns: {test_ids.columns.tolist()}")
