# 🛡️ TrustShield — Counterfeit & Malware Verification Application
**IA3 Member 1 Deliverable: Cryptographic & Static Binary Analysis Engine + Interactive Dashboard**

---

## 📌 Executive Overview
**TrustShield** is a pre-installation binary authenticity and security verification engine designed to protect Windows and Android environments from counterfeit installers, trojanized software clones, and packed evasive malware payloads.

Operating entirely statically without code execution, TrustShield extracts low-level PE/APK metadata, computes cryptographic digests in a streaming pass, evaluates byte-level Shannon Entropy, verifies Authenticode certificate chains, and cross-references publisher identities against whitelist databases to flag counterfeit clones.

---

## 🏗️ Architecture & Project Directory Tree

```
trustshield-member1/
├── app.py                          # Streamlit 'TrustShield' Interactive UI & Nutrition Label Dashboard
├── cli_scanner.py                  # IA3 Command-Line Script (takes file path -> outputs JSON)
├── requirements.txt                # pefile, signify, streamlit, plotly, pandas
├── analyzer/
│   ├── __init__.py
│   ├── ingestion.py                # Safe chunked ingestion, magic bytes, extension masquerading
│   ├── core_pipeline.py            # Main analyze_binary(filepath) orchestrator returning IA3 JSON
│   ├── crypto_hash.py              # hashlib (MD5, SHA1, SHA256) + pefile Imphash + threat DB
│   ├── cert_verifier.py            # signify Authenticode verification + Clone Identity Mismatch logic
│   ├── entropy_math.py             # math.log2 Shannon Entropy calculator (file-wide & per-section)
│   └── pe_apk_parser.py            # pefile section analysis, W+X check, timestamp check, IAT API scanner
├── data/
│   ├── known_publishers.json       # Official publisher whitelist (Google, VideoLAN, Microsoft, etc.)
│   ├── suspicious_apis.json        # Categorized dangerous Windows API dictionary
│   └── known_bad_hashes.json       # Offline sample SHA-256 threat hash feed
├── demo_samples/                   # 4 Safe demonstration test binaries
│   ├── sample1_clean_signed_sim.exe
│   ├── sample2_fake_chrome_clone.exe
│   ├── sample3_packed_high_entropy.exe
│   └── sample4_masquerading_invoice.pdf.exe
└── scripts/
    └── generate_demo_samples.py    # Generates safe test binaries for live IA3 demonstration
```

---

## 🚀 Quickstart Guide

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```
*(Dependencies: `pefile`, `signify`, `streamlit`, `plotly`, `pandas`)*

### 2. Generate Safe Demo Test Binaries
```bash
python scripts/generate_demo_samples.py
```
This generates 4 safe, non-malicious binaries in `demo_samples/` testing all static analysis features.

### 3. Run Command-Line Scanner (CLI)
Scan any PE executable or APK to get the standardized IA3 JSON report:
```bash
# Scan demo counterfeit Chrome clone
python cli_scanner.py demo_samples/sample2_fake_chrome_clone.exe

# Save JSON output to a file
python cli_scanner.py demo_samples/sample2_fake_chrome_clone.exe -o report.json

# Clean JSON piping output
python cli_scanner.py demo_samples/sample4_masquerading_invoice.pdf.exe --raw
```

### 4. Launch Interactive Web Dashboard
```bash
streamlit run app.py
```
Open your browser at `http://localhost:8501` to view:
- **Visual "Software Nutrition Label"** summary card
- Real-time **Shannon Entropy Gauge** (0.0000 - 8.0000)
- Interactive **Plotly Section Entropy Bar Chart** with 7.2 threshold
- **Suspicious IAT API** matrix categorized by MITRE ATT&CK techniques
- **Authenticode Certificate Chain** inspector
- 1-Click **"Download IA3 JSON Report"**

---

## 🧪 Demo Test Suite Matrix

| Sample Binary | Primary Test Condition | Expected Verdict | Risk Score |
| :--- | :--- | :--- | :--- |
| `sample1_clean_signed_sim.exe` | Benign PE, valid certificate, normal entropy (~4.6) | **SAFE** | 0 / 100 |
| `sample2_fake_chrome_clone.exe` | Claims `ProductName='Google Chrome'` & `CompanyName='Google LLC'` in metadata, but is **UNSIGNED** | **COUNTERFEIT / HIGH RISK** | 70 / 100 |
| `sample3_packed_high_entropy.exe` | UPX packer signatures, `UPX0` raw size 0, high Shannon entropy (~7.99), and **W+X memory permissions** | **COUNTERFEIT / HIGH RISK** | 75 / 100 |
| `sample4_masquerading_invoice.pdf.exe` | Double extension (`.pdf.exe`), MZ header, **Process Injection Triad** (`VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`) | **COUNTERFEIT / HIGH RISK** | 75 / 100 |

---

## 📄 Standardized IA3 JSON Payload Schema
The engine outputs a standardized dictionary consumed by Member 2 (Threat Intel), Member 3 (AI/ML Classifier), and Member 4 (Frontend/Reporting):

```json
{
  "file_info": {
    "filename": "sample2_fake_chrome_clone.exe",
    "size_bytes": 3584,
    "magic_bytes": "4D 5A 00 00",
    "detected_format": "Windows PE Executable",
    "extension_masquerading": false,
    "overall_shannon_entropy": 2.8503,
    "is_likely_packed": false
  },
  "hashes": {
    "md5": "35adf28a820ab236abd0b116346bf849",
    "sha1": "d86212053d99fc06b6c2e712c62ec2c2879ded3a",
    "sha256": "0e391d30a72657f1935c24b862b525caf7ae94f0acfd00f6e30d39bbaa7917a1",
    "imphash": "5a6d7433d1c8d48c14f07e3b07d042d5"
  },
  "certificate_status": {
    "is_signed": false,
    "verification_status": "UNSIGNED",
    "signer_common_name": null,
    "issuer_ca": null,
    "serial_number": null,
    "valid_from": null,
    "valid_to": null,
    "claimed_product_name": "Google Chrome",
    "claimed_company_name": "Google LLC",
    "clone_mismatch_detected": true
  },
  "pe_metadata": {
    "compile_timestamp": "2024-03-24T10:27:12+00:00",
    "timestamp_anomaly": false,
    "sections": [
      {"name": ".text", "virtual_size": 1024, "raw_size": 1024, "entropy": 4.6, "wx_risk": false},
      {"name": ".rdata", "virtual_size": 106, "raw_size": 1024, "entropy": 0.4833, "wx_risk": false},
      {"name": ".rsrc", "virtual_size": 508, "raw_size": 1024, "entropy": 1.6552, "wx_risk": false}
    ],
    "suspicious_imports": []
  },
  "risk_assessment": {
    "risk_score": 70,
    "verdict": "COUNTERFEIT / HIGH RISK",
    "reasons": [
      "File claims to be Google Chrome but lacks a valid Google LLC digital signature (CRITICAL: Counterfeit Clone Alert)"
    ]
  }
}
```

---

## 👨‍💻 Member 1 Information
- **Lead Role**: Cryptographic & Static Binary Lead
- **Team**: MalDetect-AI Project
- **Module**: Ingestion, Hashing, Authenticode Verification, PE/APK Parsing, Shannon Entropy
