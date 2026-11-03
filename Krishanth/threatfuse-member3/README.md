# 🛡️ ThreatFuse — 3-Pillar Threat Consensus & Final Decision Engine
**IA3 Member 3 Deliverable: Threat Intelligence & Decision Engine Lead**

---

## 📌 Executive Overview
**ThreatFuse** is the master decision gateway of the MalDetect-AI project. It queries external threat intelligence APIs (VirusTotal API v3 & MalwareBazaar API), incorporates static binary analysis from Member 1 and machine learning probabilities from Member 2, and evaluates a unified **Final Pre-Execution Trust Score** (0.0 to 100.0) with dynamic Zero-Day weight shifting.

The system features:
1. **Live Cloud API Integration**: VirusTotal API v3 (`GET /api/v3/files/{sha256}`) & MalwareBazaar (`POST /api/v1/` with SHA-256 and Imphash hunting).
2. **Offline Resilience**: Built-in JSON simulation cache (`data/offline_ti_cache.json`) for seamless evaluation without API rate limits or network issues.
3. **Dynamic Zero-Day Weight Shifting**: Automatically redistributes weights (55% ML + 45% Static) when cloud APIs return 404 (Zero-Day) so unknown malware cannot slip through.
4. **Hard Kill-Switch Overrides**: Automatically floors risk at $\ge 90.0$ (Trust Score $\le 10.0$) if confirmed in MalwareBazaar, flagged by $\ge 5$ VT engines, or detected as a counterfeit clone mismatch.
5. **Actionable Security Guidance**: Maps final scores into `ALLOW` (75–100), `WARN_USER` (40–74.9), or `BLOCK_AND_QUARANTINE` (0–39.9).

---

## 🏗️ Architecture & Project Directory Tree

```
threatfuse-member3/
├── app.py                          # Streamlit 'ThreatFuse' 3-Pillar Consensus Dashboard
├── cli_decision.py                 # IA3 CLI Script: API Lookup + Merged Final Trust Score JSON
├── requirements.txt                # requests, streamlit, plotly, pandas
├── threat_intel/
│   ├── __init__.py
│   ├── vt_client.py                # VirusTotal v3 client with rate limit (429) & 404 handler
│   ├── mb_client.py                # MalwareBazaar client (SHA-256 & Imphash hunter)
│   └── cache_manager.py            # Local cache manager for offline demo reliability
├── decision_engine/
│   ├── __init__.py
│   └── trust_scorer.py             # Dynamic Weighted Risk & Final Trust Score (0-100) engine
├── data/
│   ├── offline_ti_cache.json       # Cached VT & MalwareBazaar responses for 4 demo scenarios
│   └── sample_m1_m2_inputs.json    # Paired Member 1 & Member 2 test payloads
├── tests/
│   └── test_decision_engine.py     # Unit tests verifying weight shifting & kill-switch rules
└── README.md                       # Complete documentation & usage guide
```

---

## 🚀 Quickstart Guide

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```
*(Packages: `requests`, `streamlit`, `plotly`, `pandas`)*

### 2. Run Automated Unit Tests
```bash
python tests/test_decision_engine.py
```
Validates:
- Scenario 1 (Clean VLC): Trust Score $\ge 75.0 \rightarrow$ `ALLOW`
- Scenario 2 (Fake Chrome Trojan): Hard Kill-Switch Overrides $\rightarrow$ `BLOCK_AND_QUARANTINE` (Trust Score $< 10.0$)
- Scenario 3 (Zero-Day Packed): Dynamic Zero-Day Weight Shift Verified (55% ML / 45% Static / 0% Cloud TI)
- Scenario 4 (Grayware / Adware): Trust Score $42.9 \rightarrow$ `WARN_USER`

### 3. Run Command-Line Tool (CLI)
```bash
# Run standard Scenario 2 (Counterfeit Chrome clone):
python cli_decision.py --scenario 2

# Run Scenario 3 (Zero-Day packed installer):
python cli_decision.py --scenario 3

# Query by custom hash:
python cli_decision.py --sha256 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

# Output raw JSON to file:
python cli_decision.py --scenario 2 -o final_report.json
```

### 4. Launch Interactive Streamlit Dashboard
```bash
streamlit run app.py
```
Open **`http://localhost:8501`** to interact with:
- Visual **Final Pre-Execution Trust Score Gauge** (0 to 100)
- **3-Pillar Consensus Breakdown Chart** (Static vs. ML vs. Cloud TI)
- **VirusTotal Detection Ratio** and **MalwareBazaar YARA/Tags**
- **Critical Kill-Switch Callout**
- 1-Click **"Download Final Merged Trust Score JSON"** button

---

## ⚖️ Consensus Mathematics & Weighting Strategy

### Mode A: Cloud-Verified Consensus (Known Hash)
When hash is found on VirusTotal or MalwareBazaar:
$$\text{Final\_Risk} = (0.20 \times S_{\text{Static}}) + (0.30 \times S_{\text{ML}}) + (0.50 \times S_{\text{TI}})$$

### Mode B: Dynamic Zero-Day Weight Shifting (Unknown Hash / HTTP 404)
When hash is brand-new and unindexed by cloud feeds, 0 API hits do NOT artificially lower the risk:
$$\text{Final\_Risk} = (0.45 \times S_{\text{Static}}) + (0.55 \times S_{\text{ML}}) + (0.00 \times S_{\text{TI}})$$

### Hard Kill-Switch Overrides
If any critical threat rule is triggered:
- MalwareBazaar confirms malware, OR
- VirusTotal flags $\ge 5$ vendors, OR
- Member 1 flags Counterfeit Clone Identity Mismatch:
$$\text{Final\_Risk} = \max(\text{Final\_Risk}, 90.0) \implies \text{Final\_Trust\_Score} \le 10.0$$

---

## 📄 Standardized Merged Final JSON Payload Schema
```json
{
  "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
  "threat_intelligence": {
    "virustotal": {
      "found": true,
      "malicious_count": 48,
      "suspicious_count": 3,
      "harmless_count": 0,
      "total_engines": 72,
      "detection_ratio_pct": 68.75,
      "threat_label": "trojan.stealer/redline",
      "reputation": -84,
      "times_submitted": 14
    },
    "malwarebazaar": {
      "found": true,
      "signature_family": "RedLineStealer",
      "tags": ["exe", "upx", "stealer", "trojan"],
      "yara_rules": ["win_redline_stealer_auto", "packed_upx_executable"]
    }
  },
  "component_risk_breakdown": {
    "member1_static_risk_score": 90.0,
    "member2_ml_probability_score": 94.8,
    "member3_threat_intel_risk_score": 100.0,
    "weighting_strategy_used": "Cloud-Verified Weighted Consensus (50% TI / 30% ML / 20% Static)",
    "active_weights": {"member1_static": 0.2, "member2_ml": 0.3, "member3_ti": 0.5}
  },
  "final_decision": {
    "final_risk_score": 96.44,
    "final_trust_score": 3.56,
    "verdict": "MALICIOUS OR COUNTERFEIT / DO NOT INSTALL",
    "recommended_action": "BLOCK_AND_QUARANTINE",
    "critical_overrides_triggered": [
      "Confirmed malware in MalwareBazaar (RedLineStealer)",
      "Flagged by 48/72 vendors on VirusTotal",
      "Counterfeit Publisher Identity Mismatch detected by Member 1"
    ]
  }
}
```

---

## 👨‍💻 Member 3 Information
- **Lead Role**: Threat Intelligence & Decision Engine Lead
- **Team**: MalDetect-AI Project
- **Module**: VirusTotal v3 API, MalwareBazaar API, Offline TI Cache, Zero-Day Weight Shifting, Final Trust Score Algorithm
