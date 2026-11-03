import os
import zipfile
import json
from collections import Counter
import pandas as pd
import numpy as np

DATASET_DIR = r"C:\ENTER"

def inspect_all():
    print("=" * 80)
    print("STEP 1: INSPECTION OF DATASET DIRECTORY")
    print("=" * 80)
    
    files = sorted(os.listdir(DATASET_DIR))
    print(f"\nFiles found in {DATASET_DIR}:")
    archive_info = {}
    for f in files:
        full_path = os.path.join(DATASET_DIR, f)
        size_bytes = os.path.getsize(full_path)
        size_str = f"{size_bytes / (1024*1024):.2f} MB" if size_bytes < 1024*1024*1024 else f"{size_bytes / (1024**3):.2f} GB"
        print(f" - {f:<30} {size_str:>12}")
        if f.endswith(".zip"):
            archive_info[f] = {"path": full_path, "size_bytes": size_bytes}

    # Group train and test pairs
    modalities = ["ELF", "PDF", "APK", "Dot_Net", "Win64", "Win32"]
    
    print("\n" + "=" * 80)
    print("DATASET PAIRS & INTERNAL RECORD COUNTS")
    print("=" * 80)
    
    pair_summary = []
    
    for mod in modalities:
        train_zip = f"{mod}_train.zip"
        test_zip = f"{mod}_test.zip"
        
        train_files_count = 0
        test_files_count = 0
        train_samples_est = 0
        test_samples_est = 0
        
        if train_zip in archive_info:
            with zipfile.ZipFile(archive_info[train_zip]["path"], 'r') as z:
                train_files_count = len(z.namelist())
        if test_zip in archive_info:
            with zipfile.ZipFile(archive_info[test_zip]["path"], 'r') as z:
                test_files_count = len(z.namelist())
                
        # Known EMBER 2024 spec:
        # Win32: 30k weekly * 52 train = 1,560,000; * 12 test = 360,000
        # Win64: 10k weekly * 52 = 520,000; * 12 = 120,000
        # Dot_Net: 5k weekly * 52 = 260,000; * 12 = 60,000
        # APK: 4k weekly * 52 = 208,000; * 12 = 48,000
        # PDF: 1k weekly * 52 = 52,000; * 12 = 12,000
        # ELF: 500 weekly * 52 = 26,000; * 12 = 6,000
        spec_map = {
            "Win32": (1560000, 360000),
            "Win64": (520000, 120000),
            "Dot_Net": (260000, 60000),
            "APK": (208000, 48000),
            "PDF": (52000, 12000),
            "ELF": (26000, 6000),
        }
        train_total, test_total = spec_map.get(mod, (0, 0))
        pair_summary.append({
            "File Type": mod,
            "Train Archive": train_zip,
            "Test Archive": test_zip,
            "Train Weeks": train_files_count,
            "Test Weeks": test_files_count,
            "Total Train Records": f"{train_total:,}",
            "Total Test Records": f"{test_total:,}",
            "Total Records": f"{train_total + test_total:,}"
        })
    
    summary_df = pd.DataFrame(pair_summary)
    print(summary_df.to_string(index=False))

    # Deep inspection of sample data (using ELF and PDF as fast reference, plus examining record schema)
    print("\n" + "=" * 80)
    print("DEEP SCHEMA & RECORD INSPECTION (Sample: ELF / PDF)")
    print("=" * 80)
    
    for mod in ["ELF", "PDF"]:
        train_zip = f"{mod}_train.zip"
        if train_zip in archive_info:
            with zipfile.ZipFile(archive_info[train_zip]["path"], 'r') as z:
                sample_file = z.namelist()[0]
                with z.open(sample_file) as sf:
                    sample_lines = [json.loads(sf.readline().decode('utf-8')) for _ in range(5)]
            
            print(f"\n--- {mod} Sample Records Schema (File: {sample_file}) ---")
            rec = sample_lines[0]
            print(f"Total Top-level Fields: {len(rec)}")
            field_types = {k: type(v).__name__ for k, v in rec.items()}
            
            # Print field breakdown
            meta_fields = ['md5', 'sha1', 'sha256', 'tlsh', 'first_submission_date', 'last_analysis_date', 'detection_ratio', 'label', 'file_type', 'family', 'week_id']
            feature_fields = [k for k in rec.keys() if k not in meta_fields]
            
            print("\nMetadata / Target Fields:")
            for k in meta_fields:
                if k in rec:
                    val = rec[k]
                    print(f"  {k:<24} | Type: {field_types[k]:<10} | Sample: {str(val)[:40]}")
            
            print("\nFeature / Payload Fields:")
            for k in feature_fields:
                val = rec[k]
                length = len(val) if isinstance(val, (list, dict)) else 'N/A'
                print(f"  {k:<24} | Type: {field_types[k]:<10} | Items/Dims: {str(length):<6} | Sample: {str(val)[:40]}...")

    # Inspect label distribution across multiple weeks
    print("\n" + "=" * 80)
    print("LABEL DISTRIBUTION & DATA INTEGRITY CHECK")
    print("=" * 80)
    for mod in ["ELF", "PDF"]:
        for split, zname in [("Train", f"{mod}_train.zip"), ("Test", f"{mod}_test.zip")]:
            with zipfile.ZipFile(archive_info[zname]["path"], 'r') as z:
                flist = z.namelist()[:3] # inspect first 3 weeks
                label_counts = Counter()
                missing_labels = 0
                total_checked = 0
                for fname in flist:
                    with z.open(fname) as f:
                        for line in f:
                            d = json.loads(line)
                            lbl = d.get("label")
                            if lbl is None:
                                missing_labels += 1
                            else:
                                label_counts[lbl] += 1
                            total_checked += 1
                print(f"[{mod} {split} - Sample 3 weeks ({total_checked:,} samples)] Label counts: {dict(label_counts)}, Missing labels: {missing_labels}")

if __name__ == "__main__":
    inspect_all()

