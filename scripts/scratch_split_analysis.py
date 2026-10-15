import json
from pathlib import Path

root = Path(".")
with open(root / "data/splits/RANSHIELDSPLIT_v1.json") as f:
    v1 = json.load(f)
with open(root / "data/splits/SOURCE_PROTOCOL.json") as f:
    src = json.load(f)

challenge_ids = set(v1.get("challenge_ids", []))
train_src = set(src["train_ids"])
val_src = set(src.get("val_ids", []))
test_src = set(src["test_ids"])

print("=== SPLIT OVERLAP ANALYSIS ===")
print(f"RANSHIELDSPLIT_v1 challenge: {len(challenge_ids)}")
print(f"SOURCE_PROTOCOL train: {len(train_src)}")
print(f"SOURCE_PROTOCOL val:   {len(val_src)}")
print(f"SOURCE_PROTOCOL test:  {len(test_src)}")

print()
print(f"Overlap challenge & SRC train: {len(challenge_ids & train_src)}")
print(f"Overlap challenge & SRC val:   {len(challenge_ids & val_src)}")
print(f"Overlap challenge & SRC test:  {len(challenge_ids & test_src)}")

# Check within RANSHIELDSPLIT_v1 itself
v1_train = set(v1.get("train_ids", []))
v1_val   = set(v1.get("val_ids", []))
v1_test  = set(v1.get("test_ids", []))

print()
print(f"V1 train: {len(v1_train)}, val: {len(v1_val)}, test: {len(v1_test)}, challenge: {len(challenge_ids)}")
print(f"V1 challenge overlap with V1 train: {len(challenge_ids & v1_train)}")
print(f"V1 challenge overlap with V1 val:   {len(challenge_ids & v1_val)}")
print(f"V1 challenge overlap with V1 test:  {len(challenge_ids & v1_test)}")

all_v1 = v1_train | v1_val | v1_test | challenge_ids
all_src = train_src | val_src | test_src
print()
print(f"Total unique IDs in V1: {len(all_v1)}")
print(f"Total unique IDs in SRC: {len(all_src)}")
print(f"IDs in V1 but NOT in SRC: {len(all_v1 - all_src)}")
print(f"IDs in SRC but NOT in V1: {len(all_src - all_v1)}")

# Key: the challenge eval in run_paired_evaluation.py uses:
# - B4 model trained on SRC train set
# - Evaluated on V1 challenge IDs
# So leakage question: are V1 challenge IDs in SRC train set?
print()
print("=== CRITICAL: Challenge IDs in SRC training set ===")
print(f"Challenge IDs that appear in SOURCE_PROTOCOL TRAIN: {len(challenge_ids & train_src)}")
print("This means some challenge samples WERE SEEN during training!")
print("This is a training leakage issue for Challenge D evaluation.")

# Also check metadata columns for family info
import pandas as pd
meta = pd.read_csv(root / "data/raw/mlran/mlran_dataset_metadata.csv")
print()
print("=== METADATA FAMILY COLUMNS ===")
print(f"Columns: {list(meta.columns)}")
print(f"Unique ransomware_family values (first 20): {sorted(meta['ransomware_family'].dropna().unique())[:20]}")
print(f"family_label unique values (first 20): {sorted(meta['family_label'].dropna().unique())[:20]}")

# Check which families are in challenge vs training 
chall_meta = meta[meta["sample_id"].isin(challenge_ids)]
src_train_meta = meta[meta["sample_id"].isin(train_src)]

chall_families = set(chall_meta["ransomware_family"].dropna().unique())
train_families = set(src_train_meta["ransomware_family"].dropna().unique())
overlap_fam = chall_families & train_families

print()
print(f"Challenge families: {sorted(chall_families)}")
print(f"Training families (first 20): {sorted(list(train_families))[:20]}")
print(f"FAMILY OVERLAP (challenge vs SRC train): {sorted(overlap_fam)}")

# Also check family_label (numeric)
chall_fam_labels = set(chall_meta["family_label"].dropna().unique())
train_fam_labels = set(src_train_meta["family_label"].dropna().unique())
overlap_fam_labels = chall_fam_labels & train_fam_labels
print()
print(f"Challenge family_label values: {sorted(chall_fam_labels)}")
print(f"Family label overlap with SRC train: {sorted(overlap_fam_labels)}")
