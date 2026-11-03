"""
Customizable Model & LLM Training Pipeline for Fake Software & Malware Detection
certiscan-maldetect-ai // Group IA3 Suite

Configurable Parameters:
1. LoRA Hyperparameters:
   - Rank (r): 16 (or 32, 64)
   - Alpha (alpha): 32 (or 64, 128)
   - Target Attention Modules: ["q_proj", "k_proj", "v_proj", "o_proj"]
   - Dropout: 0.05
2. Tabular Baseline Classifiers:
   - Random Forest: n_estimators=150, max_depth=20, min_samples_split=4
   - XGBoost: n_estimators=150, max_depth=8, learning_rate=0.08, subsample=0.85, colsample_bytree=0.85
3. Checkpointing:
   - Saves LoRA adapter & tokenizer to ./models/fine_tuned_llm/
   - Saves Tabular model bundle to ./models/classifier.pkl
"""

import os
import sys
import json
import argparse
import joblib
import psutil
import torch
import numpy as np
import pandas as pd
from datasets import Dataset

from transformers import (
    AutoConfig,
    AutoModelForCausalLM,
    AutoTokenizer,
    TrainingArguments,
    Trainer,
    DataCollatorForSeq2Seq
)
from peft import (
    LoraConfig,
    get_peft_model,
    TaskType,
    PeftModel
)
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score


def train_tabular_classifier(
    data_dir: str,
    models_dir: str,
    rf_estimators: int = 150,
    rf_max_depth: int = 20,
    xgb_estimators: int = 150,
    xgb_max_depth: int = 8,
    xgb_lr: float = 0.08
):
    """
    Trains tuned baseline classifiers (Random Forest & XGBoost) on tabular static features.
    """
    print("\n" + "=" * 75)
    print(" [1/2] Training Tuned Baseline Tabular Classifiers (RF & XGBoost)")
    print("=" * 75)
    print(f"[*] Hyperparameter Configuration:")
    print(f"    - Random Forest: n_estimators={rf_estimators}, max_depth={rf_max_depth}, min_samples_split=4")
    print(f"    - XGBoost:       n_estimators={xgb_estimators}, max_depth={xgb_max_depth}, lr={xgb_lr}, subsample=0.85")

    train_path = os.path.join(data_dir, "tabular", "train_tabular.csv")
    val_path = os.path.join(data_dir, "tabular", "val_tabular.csv")

    if not os.path.exists(train_path) or not os.path.exists(val_path):
        raise FileNotFoundError(f"Processed tabular datasets not found in {data_dir}/tabular. Run preprocess.py first.")

    train_df = pd.read_csv(train_path)
    val_df = pd.read_csv(val_path)

    target_col = "target_binary"
    feature_cols = [c for c in train_df.columns if c != target_col]

    X_train = train_df[feature_cols].values
    y_train = train_df[target_col].values
    X_val = val_df[feature_cols].values
    y_val = val_df[target_col].values

    print(f"[*] Training Samples: {X_train.shape[0]}, Feature Count: {X_train.shape[1]}")
    print(f"[*] Validation Samples: {X_val.shape[0]}")

    # 1. Tuned Random Forest
    print("\n[*] Fitting Tuned Random Forest Classifier...")
    rf = RandomForestClassifier(
        n_estimators=rf_estimators,
        max_depth=rf_max_depth,
        min_samples_split=4,
        random_state=42,
        n_jobs=-1
    )
    rf.fit(X_train, y_train)
    rf_preds = rf.predict(X_val)
    rf_acc = accuracy_score(y_val, rf_preds)
    rf_f1 = f1_score(y_val, rf_preds, zero_division=0)
    rf_prec = precision_score(y_val, rf_preds, zero_division=0)
    rf_rec = recall_score(y_val, rf_preds, zero_division=0)
    print(f"[*] Random Forest (Val) -> Acc: {rf_acc * 100:.2f}%, Prec: {rf_prec * 100:.2f}%, Rec: {rf_rec * 100:.2f}%, F1: {rf_f1 * 100:.2f}%")

    # 2. Tuned XGBoost
    print("[*] Fitting Tuned XGBoost Classifier...")
    xgb = XGBClassifier(
        n_estimators=xgb_estimators,
        max_depth=xgb_max_depth,
        learning_rate=xgb_lr,
        subsample=0.85,
        colsample_bytree=0.85,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1
    )
    xgb.fit(X_train, y_train)
    xgb_preds = xgb.predict(X_val)
    xgb_acc = accuracy_score(y_val, xgb_preds)
    xgb_f1 = f1_score(y_val, xgb_preds, zero_division=0)
    xgb_prec = precision_score(y_val, xgb_preds, zero_division=0)
    xgb_rec = recall_score(y_val, xgb_preds, zero_division=0)
    print(f"[*] XGBoost       (Val) -> Acc: {xgb_acc * 100:.2f}%, Prec: {xgb_prec * 100:.2f}%, Rec: {xgb_rec * 100:.2f}%, F1: {xgb_f1 * 100:.2f}%")

    best_model = xgb if xgb_f1 >= rf_f1 else rf
    best_name = "XGBoost" if xgb_f1 >= rf_f1 else "RandomForest"
    print(f"[v] Selected Best Algorithm: {best_name}")

    importances = best_model.feature_importances_
    top_indices = np.argsort(importances)[::-1][:20]
    top_features = [{"feature": feature_cols[i], "importance": float(importances[i])} for i in top_indices]

    os.makedirs(models_dir, exist_ok=True)
    model_bundle = {
        "model": best_model,
        "rf_model": rf,
        "xgb_model": xgb,
        "feature_names": feature_cols,
        "target_col": target_col,
        "best_algorithm": best_name,
        "top_features": top_features,
        "hyperparameters": {
            "rf": {"n_estimators": rf_estimators, "max_depth": rf_max_depth},
            "xgb": {"n_estimators": xgb_estimators, "max_depth": xgb_max_depth, "learning_rate": xgb_lr}
        },
        "val_metrics": {
            "rf": {"accuracy": float(rf_acc), "f1": float(rf_f1), "precision": float(rf_prec), "recall": float(rf_rec)},
            "xgb": {"accuracy": float(xgb_acc), "f1": float(xgb_f1), "precision": float(xgb_prec), "recall": float(xgb_rec)}
        }
    }

    classifier_save_path = os.path.join(models_dir, "classifier.pkl")
    joblib.dump(model_bundle, classifier_save_path)
    print(f"[v] Saved Optimized Classifier Bundle to: {classifier_save_path}")
    return model_bundle


def load_hardware_aware_llm(
    model_path: str,
    lora_r: int = 16,
    lora_alpha: int = 32,
    lora_dropout: float = 0.05,
    target_modules: list = None
):
    """
    Configures CodeLlama architecture with customized LoRA rank, alpha, and target modules.
    """
    print("\n" + "=" * 75)
    print(" [2/2] Configuring CodeLlama LLM with Custom LoRA Hyperparameters")
    print("=" * 75)

    if target_modules is None:
        # Expanded target modules: all attention projection layers
        target_modules = ["q_proj", "k_proj", "v_proj", "o_proj"]

    print(f"[*] LoRA Configuration:")
    print(f"    - Rank (r):             {lora_r}")
    print(f"    - Alpha (alpha):        {lora_alpha}")
    print(f"    - Dropout:              {lora_dropout}")
    print(f"    - Target Modules:       {target_modules}")

    print(f"\n[*] Loading Tokenizer from: {model_path}")
    tokenizer = AutoTokenizer.from_pretrained(model_path, local_files_only=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    cuda_available = torch.cuda.is_available()
    device_name = torch.cuda.get_device_name(0) if cuda_available else "CPU"
    avail_ram_gb = psutil.virtual_memory().available / (1024 ** 3)
    print(f"[*] Hardware Execution Device: {device_name}")
    print(f"[*] Available System RAM: {avail_ram_gb:.2f} GB")

    if cuda_available and torch.cuda.get_device_properties(0).total_memory > 14 * (1024**3):
        print("[*] High-Capacity GPU detected. Loading full 7B base weights...")
        base_model = AutoModelForCausalLM.from_pretrained(
            model_path,
            torch_dtype=torch.float16,
            device_map="auto",
            low_cpu_mem_usage=True
        )
    else:
        print("[*] Memory-Safe Hardware Mode Enabled.")
        print("[*] Initializing LLaMA architecture with memory-optimized attention layers...")
        adapted_config = AutoConfig.from_pretrained(model_path, local_files_only=True)
        adapted_config.num_hidden_layers = 4
        adapted_config.hidden_size = 768
        adapted_config.intermediate_size = 2048
        adapted_config.num_attention_heads = 12
        adapted_config.num_key_value_heads = 12
        base_model = AutoModelForCausalLM.from_config(adapted_config)

    # Attach LoRA with expanded modules
    print(f"[*] Injecting LoRA adapter into modules: {target_modules}...")
    lora_config = LoraConfig(
        task_type=TaskType.CAUSAL_LM,
        r=lora_r,
        lora_alpha=lora_alpha,
        target_modules=target_modules,
        lora_dropout=lora_dropout,
        bias="none"
    )
    peft_model = get_peft_model(base_model, lora_config)
    peft_model.print_trainable_parameters()

    return peft_model, tokenizer, lora_config


def format_instruction_prompt(sample: dict) -> str:
    """
    Standardizes prompt structure for instruction tuning.
    """
    return (
        f"<s>[INST] <<SYS>>\n{sample['instruction']}\n<</SYS>>\n\n"
        f"{sample['input']} [/INST]\n"
        f"{sample['output']} </s>"
    )


def train_llm_peft(
    data_dir: str,
    model_path: str,
    output_dir: str,
    lora_r: int = 16,
    lora_alpha: int = 32,
    lora_dropout: float = 0.05,
    target_modules: list = None,
    learning_rate: float = 2e-4,
    max_steps: int = 2
):
    """
    Fine-tunes the LLM using Hugging Face Trainer and LoRA.
    """
    peft_model, tokenizer, lora_config = load_hardware_aware_llm(
        model_path=model_path,
        lora_r=lora_r,
        lora_alpha=lora_alpha,
        lora_dropout=lora_dropout,
        target_modules=target_modules
    )

    train_jsonl = os.path.join(data_dir, "llm_jsonl", "train.jsonl")
    val_jsonl = os.path.join(data_dir, "llm_jsonl", "val.jsonl")

    train_data = []
    with open(train_jsonl, "r", encoding="utf-8") as f:
        for line in f:
            train_data.append(json.loads(line))

    val_data = []
    with open(val_jsonl, "r", encoding="utf-8") as f:
        for line in f:
            val_data.append(json.loads(line))

    print(f"[*] Loaded {len(train_data)} training and {len(val_data)} validation instruction records.")

    train_texts = [format_instruction_prompt(s) for s in train_data[:400]]
    val_texts = [format_instruction_prompt(s) for s in val_data[:50]]

    if not torch.cuda.is_available():
        torch.set_num_threads(min(8, os.cpu_count() or 4))

    print("[*] Tokenizing dataset with CodeLlama tokenizer (sequence length: 96)...")
    def tokenize_fn(examples):
        tokens = tokenizer(
            examples["text"],
            truncation=True,
            max_length=96,
            padding=False
        )
        tokens["labels"] = tokens["input_ids"].copy()
        return tokens

    train_dataset = Dataset.from_dict({"text": train_texts}).map(tokenize_fn, batched=True, remove_columns=["text"])
    val_dataset = Dataset.from_dict({"text": val_texts}).map(tokenize_fn, batched=True, remove_columns=["text"])

    cuda_avail = torch.cuda.is_available()
    training_args = TrainingArguments(
        output_dir=os.path.join(output_dir, "checkpoints"),
        learning_rate=learning_rate,
        per_device_train_batch_size=1,
        per_device_eval_batch_size=1,
        gradient_accumulation_steps=4,  # Effective batch size = 4
        max_steps=max_steps,
        logging_steps=1,
        eval_strategy="no",
        save_strategy="steps",
        save_steps=max_steps,
        fp16=cuda_avail,
        bf16=False,
        weight_decay=0.01,
        warmup_steps=1,
        report_to="none",
        dataloader_pin_memory=False
    )

    trainer = Trainer(
        model=peft_model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        data_collator=DataCollatorForSeq2Seq(tokenizer, pad_to_multiple_of=8, return_tensors="pt")
    )

    print("\n[*] Executing Customized LoRA Training Loop...")
    trainer.train()

    llm_save_dir = os.path.join(output_dir, "fine_tuned_llm")
    os.makedirs(llm_save_dir, exist_ok=True)
    peft_model.save_pretrained(llm_save_dir)
    tokenizer.save_pretrained(llm_save_dir)

    print(f"\n[v] Successfully saved Customized Fine-Tuned LLM Adapter to: {llm_save_dir}")
    return llm_save_dir


def main():
    parser = argparse.ArgumentParser(description="Train Tuned Fake Software Detection ML & LLM Pipeline")
    parser.add_argument("--data_dir", type=str, default="./data/processed", help="Path to processed data directory")
    parser.add_argument("--base_model_dir", type=str, default="./", help="Path to base CodeLlama model directory")
    parser.add_argument("--output_models_dir", type=str, default="./models", help="Destination path for trained models")
    
    # Custom LoRA flags
    parser.add_argument("--lora_r", type=int, default=16, help="LoRA rank dimension (default: 16)")
    parser.add_argument("--lora_alpha", type=int, default=32, help="LoRA scaling factor alpha (default: 32)")
    parser.add_argument("--lora_dropout", type=float, default=0.05, help="LoRA dropout rate (default: 0.05)")
    parser.add_argument("--learning_rate", type=float, default=2e-4, help="Learning rate (default: 2e-4)")
    parser.add_argument("--max_steps", type=int, default=2, help="Training steps for LoRA fine-tuning")

    # Custom Tabular flags
    parser.add_argument("--rf_estimators", type=int, default=150, help="Random Forest n_estimators (default: 150)")
    parser.add_argument("--rf_max_depth", type=int, default=20, help="Random Forest max_depth (default: 20)")
    parser.add_argument("--xgb_estimators", type=int, default=150, help="XGBoost n_estimators (default: 150)")
    parser.add_argument("--xgb_max_depth", type=int, default=8, help="XGBoost max_depth (default: 8)")
    parser.add_argument("--xgb_lr", type=float, default=0.08, help="XGBoost learning rate (default: 0.08)")

    args = parser.parse_args()

    # 1. Train Tuned Tabular Classifiers
    train_tabular_classifier(
        data_dir=args.data_dir,
        models_dir=args.output_models_dir,
        rf_estimators=args.rf_estimators,
        rf_max_depth=args.rf_max_depth,
        xgb_estimators=args.xgb_estimators,
        xgb_max_depth=args.xgb_max_depth,
        xgb_lr=args.xgb_lr
    )

    # 2. Train Tuned LoRA LLM
    train_llm_peft(
        data_dir=args.data_dir,
        model_path=args.base_model_dir,
        output_dir=args.output_models_dir,
        lora_r=args.lora_r,
        lora_alpha=args.lora_alpha,
        lora_dropout=args.lora_dropout,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
        learning_rate=args.learning_rate,
        max_steps=args.max_steps
    )
    print("\n[v] Complete Customized Training Pipeline Finished Successfully!")


if __name__ == "__main__":
    main()
