# 🛡️ CertiScan Studio // MalDetect-AI Unified Defense-in-Depth Suite
### Group IA3: Pre-Install Counterfeit Software & Malware Detection Platform

> **A production-ready, modular cybersecurity platform integrating Cryptographic Verification, Static Binary Forensics, Dual-AI Anomaly Classifiers (Windows PE + EMBER2024 Cross-Platform Deep Binary), and Cloud Threat Intelligence Consensus into an automated multi-stage pipeline.**

---

## 👥 IA3 Research Team & Deliverables

| Member / Component | Specialization & Role | Component Directory | Core Technologies & Deliverables |
| :--- | :--- | :--- | :--- |
| **Daniel** | **Member 1:** Cryptographic & Static Binary Lead | `Daniel/trustshield-member1/` | `hashlib`, `pefile`, `signify`, `math`. Hashes (MD5, SHA-1, SHA-256, Imphash), Authenticode signature verification, Shannon entropy math, PE section telemetry, W+X shellcode risk checks, CLI scanner, and 4 test binaries. |
| **Jerom** | **Member 2:** ML Anomaly & Repacking Probability Lead | `Jerom/trustshield-member2/` | `scikit-learn`, `xgboost`, `joblib`, `pandas`. 12-dimensional static feature normalizer, trained XGBoost classifier (`trained_model.pkl`), feature impact explanations, and inference engine. |
| **Krishanth** | **Member 3:** Threat Intel & Consensus Decision Lead | `Krishanth/threatfuse-member3/` | `requests`, VirusTotal v3, MalwareBazaar, Dynamic Zero-Day Weight Shifting, kill-switch overrides, and 3-Pillar weighted consensus trust scorer. |
| **Rohith** | **Member 4:** Frontend UI & System Integration Lead | `Rohith/certiscan-maldetect-ai/` | `streamlit`, `plotly`, `fpdf2`. Master multi-stage pipeline orchestrator, Plotly visual analytics suite, Software Security Nutrition Facts card, Counterfeit Clone Diff Inspector, and FPDF2 Forensic Audit PDF generator. |
| **AI Model 2** | **Deep Binary & Cross-Platform Classifier** | `AI model 2/` | `lightgbm`, `scikit-learn`, `numpy`, `matplotlib`, `seaborn`. 620-dimensional universal byte & entropy modeling trained on the chronological EMBER 2024 benchmark (64,000 samples: 52k train + 12k held-out test). Champion LightGBM achieving **95.08% Accuracy**, **96.53% Recall**, and **0.9906 ROC-AUC**. |

---

## 🧠 Technical Interpretation of AI Model 2

### 1. What is AI Model 2?
**AI Model 2** is a specialized, deep-binary machine learning classifier designed to analyze raw executable binaries (ELF Linux/Android native libraries, Windows PE, raw shellcode, and embedded formats) and standardized EMBER JSON feature records.

Unlike traditional signature scanners that rely solely on known hashes or static header rules:
- **Chronological Benchmark Dataset**: Trained on **52,000 samples** spanning Weeks 1 to 52, and strictly evaluated against **12,000 unseen future samples** spanning Weeks 53 to 64 from the EMBER 2024 benchmark. This enforces **zero temporal data leakage** and accurately benchmarks real-world performance against evolving zero-day malware.
- **620-Dimensional Universal Feature Space**:
  - `000–255` (256 dims): **Byte Histogram** (normalized probability distribution of all 256 byte values).
  - `256–511` (256 dims): **Byte Entropy Histogram** (sliding-window Shannon entropy across file offsets).
  - `512–607` (96 dims): **Printable ASCII Distribution** (character frequency of strings).
  - `608–611` (4 dims): **String Scalar Properties** (total count, average length, printable bytes, string entropy).
  - `612–615` (4 dims): **General File Properties** (raw size, log size, global Shannon entropy, PE flag).
  - `616–619` (4 dims): **Magic / Header Start Bytes**.

### 2. Candidate Model Benchmarks & Champion Selection
Four distinct machine learning architectures were trained and evaluated on the 12,000 chronological held-out test set:

| Model Architecture | Accuracy | Precision | Recall | F1-Score | ROC-AUC | Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **LightGBM** | **95.08%** | **93.81%** | **96.53%** | **0.9515** | **0.9906** | 🏆 **CHAMPION MODEL** |
| **Random Forest** | 95.05% | 94.56% | 95.60% | 0.9508 | 0.9885 | Strong Baseline |
| **Soft-Voting Ensemble** | 94.97% | 93.77% | 96.33% | 0.9503 | 0.9904 | Multi-model blend |
| **XGBoost** | 94.87% | 93.70% | 96.20% | 0.9493 | 0.9891 | Alternative gradient booster |

**Champion Performance Metrics:**
- **Accuracy**: `95.08%`
- **Recall**: `96.53%` (minimizes dangerous false negatives)
- **ROC-AUC**: `0.9906`
- **Confusion Matrix on 12,000 Test Samples**:
  - True Negatives: **5,618** | False Positives: **382**
  - False Negatives: **208**  | True Malicious: **5,792**

---

## 🏗️ End-to-End System Architecture

```
                          [ Target Binary: .exe / .dll / .msi / .apk / .elf / .bin ]
                                                      │
                         ┌────────────────────────────┴───────────────────────────┐
                         ▼                                                        ▼
      ┌──────────────────────────────────────────────┐         ┌──────────────────────────────────────────────┐
      │ STAGE 1: Daniel (Member 1)                   │         │ AI MODEL 2: EMBER2024 Deep Binary Classifier │
      │ • Hashes: MD5, SHA-1, SHA-256, Imphash       │         │ • 620-Dimensional Universal Feature Space    │
      │ • Authenticode: Signify Digital Certificate  │         │ • 256-Bin Byte Histogram + Sliding Entropy   │
      │ • Shannon Entropy Math & W+X Shellcode Flags │         │ • LightGBM Champion Inference (AUC: 0.9906)  │
      └──────────────────────┬───────────────────────┘         └──────────────────────┬───────────────────────┘
                             │ Static Telemetry                                       │ Deep Binary Prob
                             ▼                                                        │
      ┌──────────────────────────────────────────────┐                                │
      │ STAGE 2: Jerom (Member 2)                    │                                │
      │ • 12-Dimensional PE Feature Normalization    │                                │
      │ • XGBoost Classifier Inference (PE Repacking)│                                │
      └──────────────────────┬───────────────────────┘                                │
                             │                                                        │
                             ▼                                                        │
      ┌──────────────────────────────────────────────┐                                │
      │ STAGE 3: Krishanth (Member 3)                │                                │
      │ • Cloud Threat Intel: VirusTotal v3 & MB     │                                │
      │ • Dynamic Zero-Day Weight Shifting           │                                │
      │ • Kill-Switch Overrides (Clone & Injection)  │                                │
      │ • Consensus Trust Score & Action Directive   │                                │
      └──────────────────────┬───────────────────────┘                                │
                             │                                                        │
                             ▼                                                        ▼
      ┌───────────────────────────────────────────────────────────────────────────────────────────────────────┐
      │ STAGE 4: Rohith (Member 4) - Unified CertiScan Studio Master Portal                                   │
      │ • Dual-AI Dashboard: Jerom XGBoost PE Model + AI Model 2 EMBER2024 Deep Binary Telemetry              │
      │ • Plotly Visual Analytics (Speedometer Gauge, 3-Pillar Breakdown, Section Entropies, Feature Bars)    │
      │ • Software Security Nutrition Facts Card & Counterfeit Clone Diff Inspector                           │
      │ • 1-Click Forensic Audit PDF Export (FPDF2) & Standardized Merged IA3 JSON Telemetry                  │
      └───────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## ⚡ Quick Start & Deployment Guide

### Option 1: Master Unified Dashboard (Recommended)
Launches the full interactive CertiScan Studio web application containing all 4 members' portals plus AI Model 2:
- **Windows Batch**: Double-click `run_dashboard.bat`
- **PowerShell**: Run `.\run_dashboard.ps1`
- **Direct Terminal**:
  ```bash
  py -m streamlit run app.py
  ```
*Opens automatically at `http://localhost:8501`.*

### Option 2: Standalone AI Model 2 Portal
Launches the dedicated EMBER2024 deep-binary research and benchmarking dashboard:
- **Windows Batch**: Double-click `run_ai_model_2.bat`
- **PowerShell**: Run `.\run_ai_model_2.ps1`
- **Direct Terminal**:
  ```bash
  cd "AI model 2"
  py -m streamlit run streamlit_app.py --server.port 8502
  ```
*Opens at `http://localhost:8502`.*

### Option 3: Master Terminal CLI (`cli_master.py`)
Scan any binary or evaluate pre-verified scenarios directly from the command line:
```bash
# 1. Full security analysis of a binary with dual-AI telemetry and PDF/JSON export:
py cli_master.py Daniel/trustshield-member1/demo_samples/sample1_clean_signed_sim.exe --pdf-out audit.pdf --json-out telemetry.json

# 2. Test AI Model 2 directly on an unseen held-out test sample (index 0 to 11999):
py cli_master.py --test-ai2 0

# 3. Evaluate standard demo scenario 2 (Counterfeit Chrome Trojan):
py cli_master.py --scenario 2
```

---

## 🧪 Automated Testing Suite (21/21 Tests Passing)

Execute the complete end-to-end unit and integration test suite across all 4 member modules and AI Model 2:
- **Windows Batch**: Double-click `run_all_tests.bat`
- **PowerShell**: Run `.\run_all_tests.ps1`
- **Direct Pytest**:
  ```bash
  py -m pytest Jerom/trustshield-member2/tests Krishanth/threatfuse-member3/tests Rohith/certiscan-maldetect-ai/tests "AI model 2/tests" -v
  ```

### Test Coverage Breakdown:
- **Member 2 Inference Tests (`Jerom/trustshield-member2/tests/test_inference.py`)**: 5/5 PASSED
  - Validates clean sample classification, counterfeit clone high probability, packed binary high entropy, masquerading invoice detection, and missing key handling.
- **Member 3 Decision Engine Tests (`Krishanth/threatfuse-member3/tests/test_decision_engine.py`)**: 4/4 PASSED
  - Validates Scenario 1 clean VLC trust consensus (>98%), Scenario 2 kill-switch activation (<10%), Scenario 3 dynamic zero-day weight shifting (55% ML / 45% Static / 0% TI), and Scenario 4 grayware calibration.
- **Member 4 Master Integration Tests (`Rohith/certiscan-maldetect-ai/tests/test_full_integration.py`)**: 8/8 PASSED
  - Validates end-to-end pipeline on all 4 scenarios, Plotly figure generation, HTML Nutrition Label rendering, FPDF2 PDF byte generation, and live execution on real binaries.
- **AI Model 2 Tests (`AI model 2/tests/test_ai_model_2.py`)**: 4/4 PASSED
  - Validates model metadata benchmarks (accuracy > 94%, ROC-AUC > 0.98), 620-dimensional feature extraction, held-out test sample classification, and live binary byte extraction.

---

## 📂 Project Structure

```
├── app.py                              # Master Unified Portal (Members 1-4 + AI Model 2 + Test Hub)
├── cli_master.py                       # Unified Terminal CLI Tool with Dual-AI Support
├── requirements.txt                    # Consolidated Project Dependencies
├── run_dashboard.bat                   # 1-Click Master Web Launcher (Port 8501)
├── run_dashboard.ps1                   # 1-Click Master PowerShell Launcher
├── run_ai_model_2.bat                  # 1-Click Standalone AI Model 2 Launcher (Port 8502)
├── run_ai_model_2.ps1                  # 1-Click Standalone AI Model 2 PowerShell Launcher
├── run_all_tests.bat                   # 1-Click Batch Test Runner (All 21 Tests)
├── run_all_tests.ps1                   # 1-Click PowerShell Test Runner
│
├── AI model 2/                         # AI Model 2: EMBER2024 Deep Binary Modality
│   ├── inference.py                    # Production inference engine & raw binary extractor
│   ├── preprocess.py                   # 620-dim feature normalizer & EmberPreprocessor
│   ├── streamlit_app.py                # Standalone AI Model 2 Streamlit dashboard
│   ├── train.py                        # Model comparison & training pipeline
│   ├── inspect_dataset.py              # Dataset schema & archive inspector
│   ├── models/                         # Champion LightGBM weights, preprocessor, and plots
│   ├── processed/                      # 12,000 held-out test samples (X_test, y_test, meta)
│   └── tests/                          # Automated unit tests for AI Model 2
│
├── Daniel/trustshield-member1/         # Member 1: Cryptographic & Static Binary Lead
│   ├── analyzer/                       # Core static analysis pipeline
│   ├── cli_scanner.py                  # Member 1 CLI binary scanner
│   ├── app.py                          # Member 1 Streamlit portal
│   └── demo_samples/                   # Live test binary executables
│
├── Jerom/trustshield-member2/          # Member 2: ML Anomaly & Repacking Probability Lead
│   ├── ml_engine/                      # Feature extraction & inference engine
│   ├── trained_model.pkl               # Trained XGBoost v1.2 classifier model
│   ├── cli_predict.py                  # Member 2 CLI anomaly classifier
│   └── tests/                          # 5 Unit tests
│
├── Krishanth/threatfuse-member3/      # Member 3: Threat Intelligence & Consensus Lead
│   ├── threat_intel/                   # VirusTotal v3 & MalwareBazaar clients
│   ├── decision_engine/                # Consensus & Dynamic Zero-Day scorer
│   ├── cli_decision.py                 # Member 3 CLI decision tool
│   └── tests/                          # 4 Unit tests
│
└── Rohith/certiscan-maldetect-ai/      # Member 4: Frontend UI & System Integration Lead
    ├── integration/                    # Pipeline orchestrator & AI Model 2 adapter
    ├── reporting/                      # FPDF2 forensic audit PDF report generator
    ├── ui_components/                  # Plotly visual analytics & HTML Nutrition labels
    └── tests/                          # 8 Unit & end-to-end integration tests
```
