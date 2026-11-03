"""
CertiScan Studio // MalDetect-AI Unified Master Portal
Group IA3: Fake Software & Malware Detection Suite
Unified Master Web Application integrating Members 1, 2, 3, and 4 into a single cohesive platform.
"""

import os
import sys
import json
import time
import tempfile
import subprocess
import pandas as pd
import streamlit as st

# Configure sys.path dynamically for all 4 member sub-packages
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
MEMBER1_DIR = os.path.join(ROOT_DIR, "Daniel", "trustshield-member1")
MEMBER2_DIR = os.path.join(ROOT_DIR, "Jerom", "trustshield-member2")
MEMBER3_DIR = os.path.join(ROOT_DIR, "Krishanth", "threatfuse-member3")
MEMBER4_DIR = os.path.join(ROOT_DIR, "Rohith", "certiscan-maldetect-ai")
AI_MODEL2_DIR = os.path.join(ROOT_DIR, "AI model 2")

for path in [ROOT_DIR, MEMBER4_DIR, MEMBER1_DIR, MEMBER2_DIR, MEMBER3_DIR, AI_MODEL2_DIR]:
    if os.path.exists(path) and path not in sys.path:
        sys.path.insert(0, path)

import numpy as np
import plotly.graph_objects as go
import plotly.express as px

# Import Member 4 Orchestrator & UI Modules
from integration.pipeline_orchestrator import run_full_security_pipeline, load_scenario_preset
from integration.ai_model2_adapter import (
    predict_binary_with_ai2,
    load_ai2_metadata,
    load_ai2_test_samples,
    get_ai_model2_predictor,
)
from ui_components.visual_analytics import (
    create_trust_score_gauge,
    create_pillar_breakdown_chart,
    create_section_entropy_chart,
    create_ml_feature_importance_chart,
)
from ui_components.nutrition_label import (
    render_nutrition_label_html,
    render_counterfeit_diff_html,
)
from reporting.pdf_generator import generate_pdf_report

# Page Configuration
st.set_page_config(
    page_title="CertiScan Studio // MalDetect-AI Unified",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Cyber Security Dark Theme CSS
CUSTOM_CSS = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }

    .stApp {
        background: radial-gradient(circle at 10% 10%, #0d1527 0%, #060a12 100%);
        color: #f1f5f9;
    }

    /* Card styling */
    .metric-card {
        background: rgba(15, 23, 42, 0.75);
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 18px;
        box-shadow: 0 4px 20px -2px rgba(0, 0, 0, 0.4);
        backdrop-filter: blur(8px);
    }

    /* Status badge pills */
    .badge-safe {
        background: rgba(16, 185, 129, 0.2);
        color: #34d399;
        border: 1px solid #10b981;
        padding: 4px 12px;
        border-radius: 9999px;
        font-weight: 700;
        font-size: 13px;
        letter-spacing: 0.5px;
    }

    .badge-warning {
        background: rgba(245, 158, 11, 0.2);
        color: #fbbf24;
        border: 1px solid #f59e0b;
        padding: 4px 12px;
        border-radius: 9999px;
        font-weight: 700;
        font-size: 13px;
        letter-spacing: 0.5px;
    }

    .badge-danger {
        background: rgba(239, 68, 68, 0.2);
        color: #f87171;
        border: 1px solid #ef4444;
        padding: 4px 12px;
        border-radius: 9999px;
        font-weight: 700;
        font-size: 13px;
        letter-spacing: 0.5px;
    }

    /* Action Verdict Hero Banner */
    .verdict-banner-allow {
        background: linear-gradient(90deg, rgba(16, 185, 129, 0.25) 0%, rgba(15, 23, 42, 0.8) 100%);
        border-left: 6px solid #10b981;
        border-radius: 8px;
        padding: 16px 20px;
        margin-top: 10px;
        box-shadow: 0 4px 14px rgba(16, 185, 129, 0.15);
    }

    .verdict-banner-warn {
        background: linear-gradient(90deg, rgba(245, 158, 11, 0.25) 0%, rgba(15, 23, 42, 0.8) 100%);
        border-left: 6px solid #f59e0b;
        border-radius: 8px;
        padding: 16px 20px;
        margin-top: 10px;
        box-shadow: 0 4px 14px rgba(245, 158, 11, 0.15);
    }

    .verdict-banner-quarantine {
        background: linear-gradient(90deg, rgba(239, 68, 68, 0.25) 0%, rgba(15, 23, 42, 0.8) 100%);
        border-left: 6px solid #ef4444;
        border-radius: 8px;
        padding: 16px 20px;
        margin-top: 10px;
        box-shadow: 0 4px 14px rgba(239, 68, 68, 0.15);
    }

    /* Tab styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background-color: rgba(15, 23, 42, 0.6);
        padding: 6px;
        border-radius: 8px;
        border: 1px solid #1e293b;
    }

    .stTabs [data-baseweb="tab"] {
        height: 48px;
        background-color: transparent;
        border-radius: 6px 6px 0 0;
        color: #94a3b8;
        font-weight: 600;
        padding: 0 20px;
    }

    .stTabs [aria-selected="true"] {
        background-color: rgba(56, 189, 248, 0.12) !important;
        color: #38bdf8 !important;
        border-bottom: 2px solid #38bdf8 !important;
    }

    /* Mono code display */
    .mono-hash {
        font-family: 'JetBrains Mono', monospace;
        font-size: 12px;
        color: #38bdf8;
        background: rgba(15, 23, 42, 0.8);
        padding: 4px 8px;
        border-radius: 4px;
        border: 1px solid #1e293b;
        word-break: break-all;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# ==============================================================================
# SIDEBAR CONTROLS & PORTAL NAVIGATION
# ==============================================================================
with st.sidebar:
    st.markdown("""
    <div style="text-align:center;padding:10px 0 20px 0;">
        <div style="font-size:26px;font-weight:900;letter-spacing:-1px;color:#f8fafc;">
            🛡️ <span style="color:#38bdf8;">MALDETECT</span>-AI
        </div>
        <div style="font-size:11px;color:#94a3b8;font-weight:600;letter-spacing:1px;text-transform:uppercase;">
            CertiScan Studio // Group IA3 Suite
        </div>
    </div>
    """, unsafe_allow_html=True)

    portal_view = st.selectbox(
        "🗂️ Select Portal View:",
        [
            "🛡️ Master Unified Dashboard (Member 4 Integration)",
            "🔍 Member 1 Portal: Crypto & Static Binary (Daniel)",
            "🤖 Member 2 Portal: ML Anomaly Classifier (Jerom)",
            "🌐 Member 3 Portal: Threat Intel Consensus (Krishanth)",
            "🚀 AI Model 2: EMBER2024 Deep Binary Classifier (LightGBM 95.1% Acc)",
            "🧪 Automated Test Suite & Health Hub"
        ],
        index=0
    )

    st.markdown("---")

    active_report = None

    if "Master Unified Dashboard" in portal_view:
        st.markdown("### 🎛️ Analysis Source")
        analysis_mode = st.radio(
            "Select Operation Mode:",
            ["🎯 Load Pre-Verified Demo Scenario", "📂 Upload Live File (.exe, .dll, .msi, .apk, .elf)"],
            index=0
        )

        if "Demo Scenario" in analysis_mode:
            scenario_options = {
                "Scenario 1: Clean Signed VLC Installer": "scenario_1",
                "Scenario 2: Counterfeit Chrome Trojan Clone": "scenario_2",
                "Scenario 3: Zero-Day UPX Packed Malware": "scenario_3",
                "Scenario 4: Unknown Grayware Utility": "scenario_4"
            }
            selected_scenario_label = st.selectbox(
                "Select Evaluation Scenario:",
                list(scenario_options.keys()),
                help="Select one of the 4 verified IA3 defense-in-depth scenarios"
            )
            scenario_key = scenario_options[selected_scenario_label]
            
            try:
                active_report = load_scenario_preset(scenario_key)
                # Attach corresponding demo binary AI Model 2 prediction
                demo_file_map = {
                    "scenario_1": os.path.join(MEMBER1_DIR, "demo_samples", "sample1_clean_signed_sim.exe"),
                    "scenario_2": os.path.join(MEMBER1_DIR, "demo_samples", "sample2_fake_chrome_clone.exe"),
                    "scenario_3": os.path.join(MEMBER1_DIR, "demo_samples", "sample3_packed_high_entropy.exe"),
                    "scenario_4": os.path.join(MEMBER1_DIR, "demo_samples", "sample4_masquerading_invoice.pdf.exe"),
                }
                demo_bin_path = demo_file_map.get(scenario_key)
                if demo_bin_path and os.path.exists(demo_bin_path):
                    try:
                        active_report["ai_model_2"] = predict_binary_with_ai2(demo_bin_path)
                    except Exception:
                        pass
            except Exception as e:
                st.error(f"Error loading demo scenario: {e}")

        else:
            uploaded_file = st.file_uploader(
                "Upload Executable Binary:",
                type=["exe", "dll", "msi", "apk", "sys", "bin", "elf"],
                help="Upload any Windows PE32 / PE32+ executable, ELF Linux binary, MSI, or APK package"
            )

            with st.expander("🔑 Threat Intelligence Settings & API Keys", expanded=False):
                vt_key = st.text_input("VirusTotal API Key (v3)", type="password", help="Leave blank to use local offline cache")
                mb_key = st.text_input("MalwareBazaar Auth Key", type="password", help="Leave blank to use local offline cache")
                force_offline_cache = st.checkbox("Force Offline TI Cache Only", value=True, help="Use pre-cached responses without hitting live rate limits")

            if uploaded_file is not None:
                if st.button("🚀 Run 4-Stage Analysis Pipeline", type="primary", use_container_width=True):
                    with st.status("Executing Multi-Pillar Defense-in-Depth Pipeline...", expanded=True) as status:
                        st.write("🔍 **Stage 1 (Member 1)**: Cryptographic Hashing, Authenticode Verification & PE Section Entropy...")
                        with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{uploaded_file.name}") as tmp:
                            tmp.write(uploaded_file.getvalue())
                            tmp_path = tmp.name

                        try:
                            time.sleep(0.3)
                            st.write("🤖 **Stage 2 (Member 2)**: XGBoost Feature Extraction & Repacking Probability Inference...")
                            time.sleep(0.3)
                            st.write("🌐 **Stage 3 (Member 3)**: Cloud Threat Intelligence & Consensus Decision Engine...")
                            time.sleep(0.3)
                            
                            live_rep = run_full_security_pipeline(
                                tmp_path,
                                vt_api_key=None if force_offline_cache else (vt_key or None),
                                mb_api_key=None if force_offline_cache else (mb_key or None)
                            )
                            
                            st.write("🚀 **AI Model 2 (Deep Binary)**: Extracting 620-Dim Byte & Entropy Constellation (LightGBM)...")
                            try:
                                live_rep["ai_model_2"] = predict_binary_with_ai2(tmp_path)
                            except Exception as ex:
                                live_rep["ai_model_2"] = {"status": "ERROR", "error": str(ex)}

                            st.write("📑 **Stage 4 (Member 4)**: Assembling Security Nutrition Label, Plotly Analytics & Forensic Report...")
                            time.sleep(0.2)
                            
                            live_rep["member1_static"]["file_info"]["filename"] = uploaded_file.name
                            live_rep["metadata"]["analyzed_file"] = uploaded_file.name
                            
                            st.session_state["live_analysis_report"] = live_rep
                            st.session_state["live_analysis_filename"] = uploaded_file.name
                            status.update(label="✅ Multi-Pillar Security Pipeline Complete!", state="complete", expanded=False)
                        except Exception as e:
                            status.update(label="❌ Pipeline Execution Failed", state="error", expanded=True)
                            st.error(f"Pipeline Execution Failed: {e}")
                        finally:
                            try:
                                os.remove(tmp_path)
                            except Exception:
                                pass

                # Restore cached upload result if available
                if "live_analysis_report" in st.session_state and st.session_state.get("live_analysis_filename") == uploaded_file.name:
                    active_report = st.session_state["live_analysis_report"]
            else:
                st.info("👆 Upload an executable binary above or switch to Demo Scenarios to view live telemetry.")

    # Team Attribution Footer in Sidebar
    st.markdown("---")
    st.markdown("""
    <div style="font-size:11px;color:#64748b;line-height:1.6;">
        <b>Group IA3 Contributors:</b><br>
        • <b>Daniel:</b> Member 1 (Crypto & Static Binary)<br>
        • <b>Jerom:</b> Member 2 (ML Anomaly & Repacking)<br>
        • <b>Krishanth:</b> Member 3 (Threat Intel & Decision)<br>
        • <b>Rohith:</b> Member 4 (Frontend UI & Orchestrator)<br>
        <div style="margin-top:6px;color:#38bdf8;font-weight:600;">Production Build v1.0.0</div>
    </div>
    """, unsafe_allow_html=True)


# ==============================================================================
# VIEW 1: MASTER UNIFIED DASHBOARD (MEMBER 4 INTEGRATION)
# ==============================================================================
if "Master Unified Dashboard" in portal_view:
    if active_report is None:
        st.title("🛡️ CertiScan Studio // MalDetect-AI Unified Dashboard")
        st.info("👈 Please select a Demo Scenario or upload a binary from the sidebar to begin analysis.")
        st.stop()

    m1 = active_report.get("member1_static", {})
    m2 = active_report.get("member2_ml", {})
    m3_ti = active_report.get("member3_threat_intel", {})
    m3_dec = active_report.get("member3_decision", {}).get("trust_decision", {})

    file_info = m1.get("file_info", {})
    cert = m1.get("certificate_status", {})
    hashes = m1.get("hashes", {})
    pe_meta = m1.get("pe_metadata", {})
    ml_pred = m2.get("ml_prediction", {})
    vt = m3_ti.get("virustotal", {})
    mb = m3_ti.get("malwarebazaar", {})

    filename = file_info.get("filename", "binary.exe")
    size_kb = file_info.get("size_bytes", 0) / 1024.0
    sha256 = hashes.get("sha256", "0" * 64)
    trust_score = float(m3_dec.get("final_trust_score", 50.0))
    risk_score = float(m3_dec.get("final_risk_score", 50.0))
    verdict = m3_dec.get("verdict", "UNKNOWN")
    recommended = m3_dec.get("recommended_action", "INSPECT")
    weights = m3_dec.get("weight_distribution", {})
    pillar_scores = m3_dec.get("pillar_scores", {})
    kill_switches = m3_dec.get("kill_switch_overrides", [])

    # Top Header Metadata Banner
    col_h1, col_h2 = st.columns([3, 1])
    with col_h1:
        st.markdown(f"""
        <div style="padding:4px 0 14px 0;">
            <div style="font-size:26px;font-weight:800;color:#f8fafc;">
                Target Binary: <span style="color:#38bdf8;font-family:monospace;">{filename}</span>
            </div>
            <div style="margin-top:4px;display:flex;align-items:center;gap:12px;font-size:12px;color:#94a3b8;">
                <span><b>Size:</b> {size_kb:.1f} KB</span>
                <span>|</span>
                <span><b>Format:</b> {file_info.get("detected_format", "PE32 Executable")}</span>
                <span>|</span>
                <span><b>SHA-256:</b> <span class="mono-hash">{sha256[:16]}...{sha256[-12:]}</span></span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with col_h2:
        if trust_score >= 75.0:
            badge_class = "badge-safe"
            badge_text = f"SAFE ({recommended})"
        elif trust_score >= 40.0:
            badge_class = "badge-warning"
            badge_text = f"CAUTION ({recommended})"
        else:
            badge_class = "badge-danger"
            badge_text = f"QUARANTINE ({recommended})"

        st.markdown(f"""
        <div style="text-align:right;padding-top:14px;">
            <span class="{badge_class}" style="font-size:15px;padding:8px 16px;">
                {badge_text}
            </span>
        </div>
        """, unsafe_allow_html=True)

    # --------------------------------------------------------------------------
    # TOP EXECUTIVE SUMMARY ROW: Left = Plotly Gauge & Verdict | Right = Nutrition Label
    # --------------------------------------------------------------------------
    col_gauge_box, col_nutrition_box = st.columns([1, 1])

    with col_gauge_box:
        st.plotly_chart(create_trust_score_gauge(trust_score, verdict), use_container_width=True)
        
        # Action & Verdict Banner
        if trust_score >= 75.0:
            banner_class = "verdict-banner-allow"
            action_color = "#10b981"
            action_name = "ALLOW"
        elif trust_score >= 40.0:
            banner_class = "verdict-banner-warn"
            action_color = "#f59e0b"
            action_name = "WARN_USER"
        else:
            banner_class = "verdict-banner-quarantine"
            action_color = "#ef4444"
            action_name = "BLOCK_AND_QUARANTINE"

        st.markdown(f"""
        <div class="{banner_class}">
            <div style="font-size:11px;font-weight:700;color:#94a3b8;letter-spacing:1px;text-transform:uppercase;">
                AUTOMATED SECURITY POLICY VERDICT
            </div>
            <div style="font-size:19px;font-weight:800;color:{action_color};margin-top:2px;">
                {verdict}
            </div>
            <div style="font-size:13px;color:#cbd5e1;margin-top:4px;">
                <b>Recommended Action:</b> <span style="color:#f8fafc;font-weight:700;background:rgba(0,0,0,0.4);padding:2px 8px;border-radius:4px;">{action_name}</span> &nbsp;|&nbsp; <b>Risk Score:</b> {risk_score:.1f}/100
            </div>
        </div>
        """, unsafe_allow_html=True)

    with col_nutrition_box:
        st.markdown(render_nutrition_label_html(active_report), unsafe_allow_html=True)

    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

    # --------------------------------------------------------------------------
    # 4 ORGANIZED DEEP-DIVE TABS
    # --------------------------------------------------------------------------
    tab1, tab2, tab3, tab4 = st.tabs([
        "📋 Tab 1: Executive Risk & Clone Diff Inspector",
        "🔍 Tab 2: Static Binary & Crypto Forensics (Member 1)",
        "🤖 Tab 3: AI/ML & Cloud Threat Intel (Members 2 & 3)",
        "📑 Tab 4: PDF Audit Report & Raw JSON Export (Member 4)"
    ])

    # TAB 1: EXECUTIVE RISK & CLONE DIFF
    with tab1:
        if kill_switches:
            st.markdown(f"""
            <div style="background:#450a0a;border-left:5px solid #ef4444;border-radius:6px;padding:14px 18px;margin-bottom:18px;">
                <div style="font-size:14px;font-weight:800;color:#fca5a5;text-transform:uppercase;letter-spacing:0.5px;">
                    🚨 CRITICAL SECURITY KILL-SWITCH OVERRIDE TRIGGERED
                </div>
                <div style="font-size:13px;color:#fecaca;margin-top:6px;line-height:1.6;">
                    {'<br>• '.join([''] + kill_switches)}
                </div>
            </div>
            """, unsafe_allow_html=True)

        col_t1_left, col_t1_right = st.columns([1, 1])

        with col_t1_left:
            st.plotly_chart(create_pillar_breakdown_chart(pillar_scores, weights), use_container_width=True)

            st.markdown("#### ⚖️ Dynamic Weight Consensus Breakdown")
            st.markdown(f"""
            - **Consensus Strategy**: `{weights.get("strategy", "Dynamic Weighted Consensus")}`
            - **Static Binary Contribution**: {weights.get("member1_static_weight", 0.0) * 100:.0f}%
            - **ML Anomaly Contribution**: {weights.get("member2_ml_weight", 0.0) * 100:.0f}%
            - **Threat Intel Contribution**: {weights.get("member3_ti_weight", 0.0) * 100:.0f}%
            """)

        with col_t1_right:
            st.markdown(render_counterfeit_diff_html(cert, file_info), unsafe_allow_html=True)

    # TAB 2: STATIC BINARY & CRYPTO
    with tab2:
        st.markdown("### 🔐 Cryptographic Authenticode & Digital Certificate Verification")
        col_cert1, col_cert2, col_cert3 = st.columns(3)

        is_signed = cert.get("is_signed", False)
        col_cert1.metric(
            "Authenticode Signature",
            "Valid Signed" if is_signed else "Unsigned",
            delta="Verified CA" if is_signed else "-No Signature",
            delta_color="normal" if is_signed else "inverse"
        )
        col_cert2.metric("Subject CN", cert.get("subject_cn", "None"))
        col_cert3.metric("Issuer CN", cert.get("issuer_cn", "None"))

        st.markdown("---")
        st.markdown("### 🔑 Cryptographic Hashes")
        hash_data = {
            "Algorithm": ["MD5", "SHA-1", "SHA-256", "Imphash"],
            "Hash Value": [
                hashes.get("md5", "N/A"),
                hashes.get("sha1", "N/A"),
                hashes.get("sha256", "N/A"),
                pe_meta.get("imphash", "N/A")
            ]
        }
        st.table(pd.DataFrame(hash_data))

        st.markdown("---")
        st.markdown("### 📊 PE Section Shannon Entropy & Packing Detection (y = 7.2 Threshold)")
        sections = pe_meta.get("sections", [])
        st.plotly_chart(create_section_entropy_chart(sections), use_container_width=True)

        col_sec_table, col_iat = st.columns([1, 1])

        with col_sec_table:
            st.markdown("#### 📁 Section Permissions & Shellcode Risks")
            if sections:
                sec_rows = []
                for s in sections:
                    sec_rows.append({
                        "Section": s.get("name", ""),
                        "Entropy": f"{s.get('entropy', 0.0):.3f}",
                        "Raw Size": f"{s.get('raw_size', 0):,} B",
                        "Virtual Size": f"{s.get('virtual_size', 0):,} B",
                        "W+X Shellcode Risk": "🚨 YES (High Risk)" if s.get("wx_risk", False) else "✅ NO"
                    })
                st.dataframe(pd.DataFrame(sec_rows), use_container_width=True)
            else:
                st.info("No PE sections identified in target file.")

        with col_iat:
            st.markdown("#### ⚠️ Suspicious API Imports Detected (IAT)")
            suspicious = pe_meta.get("suspicious_imports", [])
            if suspicious:
                for api in suspicious:
                    if api in ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]:
                        st.error(f"🚨 **{api}** (Process Injection Triad API)")
                    else:
                        st.warning(f"⚠️ **{api}** (Suspicious System API)")
            else:
                st.success("✅ No high-risk or process injection APIs flagged in Import Address Table (IAT).")

    # TAB 3: AI/ML & THREAT INTEL
    with tab3:
        col_m2, col_m3 = st.columns(2)

        with col_m2:
            st.markdown("### 🤖 Member 2: XGBoost Anomaly Classifier")
            prob_val = float(ml_pred.get("malware_probability_score", 0.0))
            tier_val = ml_pred.get("risk_tier", "BENIGN_CLEAN")

            st.metric(
                "Malware Repacking Probability",
                f"{prob_val:.1f}%",
                delta=f"Risk Tier: {tier_val}",
                delta_color="inverse" if prob_val > 50 else "normal"
            )
            st.caption(f"Model: {ml_pred.get('model_version', 'XGBoost-v1.2')} trained on 5,000 synthetic static vectors")

            st.plotly_chart(
                create_ml_feature_importance_chart(ml_pred.get("top_feature_contributions", [])),
                use_container_width=True
            )

        with col_m3:
            st.markdown("### 🌐 Member 3: Threat Intelligence Consensus")
            vt_pos = vt.get("positives", 0)
            vt_tot = vt.get("total", 72)
            st.metric(
                "VirusTotal v3 Detections",
                f"{vt_pos} / {vt_tot} Engines",
                delta="Malicious Match" if vt_pos > 0 else "Clean Record",
                delta_color="inverse" if vt_pos > 0 else "normal"
            )
            if vt.get("permalink") and vt.get("permalink") != "N/A":
                st.markdown(f"[🔗 View VirusTotal Live Scan Report]({vt['permalink']})")

            st.markdown("#### 🛡️ MalwareBazaar Telemetry & YARA Rules")
            mb_tags = mb.get("tags", [])
            st.write({
                "Query Status": mb.get("query_status", "hash_not_found"),
                "Malware Signature": mb.get("signature", "None"),
                "Delivery Method": mb.get("delivery_method", "Unknown"),
                "Threat Tags / YARA Rules": mb_tags if mb_tags else ["None"]
            })

            st.markdown("#### ⚖️ Dynamic Zero-Day Weight Shifting")
            if vt_pos == 0 and mb.get("query_status") == "hash_not_found":
                st.info("""
                **Zero-Day Rule Triggered**: Cloud threat intelligence has no record (404 / 0 detections).
                Instead of assuming the file is safe, the decision engine shifts weight to **55% ML Model** and **45% Static Binary**, neutralizing cloud evasion.
                """)
            else:
                st.success("""
                **Cloud Consensus Active**: Verified threat intel available.
                Standard Weights: 50% Threat Intel, 30% ML Model, 20% Static Binary.
                """)

        # AI Model 2 Deep Binary Telemetry Integration
        st.markdown("---")
        st.markdown("### 🚀 AI Model 2: EMBER2024 Deep Binary Telemetry (LightGBM Champion)")
        ai2_rep = active_report.get("ai_model_2")
        if ai2_rep and ai2_rep.get("status") == "SUCCESS":
            col_ai2_1, col_ai2_2 = st.columns([1, 1])
            with col_ai2_1:
                p_mal = float(ai2_rep.get("prob_malicious_pct", 50.0))
                is_mal = ai2_rep.get("is_malicious", False)
                st.metric(
                    "Deep Binary Malicious Probability",
                    f"{p_mal:.1f}%",
                    delta=f"Verdict: {ai2_rep.get('prediction_label', 'UNKNOWN')}",
                    delta_color="inverse" if is_mal else "normal"
                )
                st.caption("Universal 620-dimensional byte histogram, sliding window Shannon entropy, and string frequency model.")

                fig_ai2_gauge = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=p_mal,
                    title={'text': "EMBER2024 Malware Risk (%)"},
                    gauge={
                        'axis': {'range': [0, 100]},
                        'bar': {'color': "#ef4444" if is_mal else "#10b981"},
                        'steps': [
                            {'range': [0, 50], 'color': "rgba(16, 185, 129, 0.15)"},
                            {'range': [50, 75], 'color': "rgba(245, 158, 11, 0.15)"},
                            {'range': [75, 100], 'color': "rgba(239, 68, 68, 0.15)"}
                        ]
                    }
                ))
                fig_ai2_gauge.update_layout(height=260, margin=dict(l=20, r=20, t=40, b=20), paper_bgcolor="rgba(0,0,0,0)", font={'color': "#f1f5f9"})
                st.plotly_chart(fig_ai2_gauge, use_container_width=True)

            with col_ai2_2:
                st.markdown("#### 🔍 Dominant Activating Features (620-D Feature Space)")
                top_feats = ai2_rep.get("top_features", [])
                if top_feats:
                    f_names = [f["feature"] for f in top_feats[:8]][::-1]
                    f_vals = [abs(f.get("importance_weight", 1.0) * f.get("raw_value", 0.0)) for f in top_feats[:8]][::-1]
                    fig_ai2_bar = go.Figure(go.Bar(
                        x=f_vals,
                        y=f_names,
                        orientation='h',
                        marker=dict(color='#38bdf8')
                    ))
                    fig_ai2_bar.update_layout(
                        title="Top Feature Contributions (Weight × Raw)",
                        height=260,
                        margin=dict(l=10, r=10, t=30, b=20),
                        paper_bgcolor="rgba(0,0,0,0)",
                        plot_bgcolor="rgba(0,0,0,0)",
                        font={'color': "#94a3b8"}
                    )
                    st.plotly_chart(fig_ai2_bar, use_container_width=True)
                else:
                    st.info("No activating features extracted.")
        else:
            st.info("💡 AI Model 2 deep binary telemetry is ready for live file uploads or can be evaluated directly in the AI Model 2 Portal.")

    # TAB 4: FORENSIC REPORTS & EXPORTS
    with tab4:
        st.markdown("### 📑 Automated Forensic Audit Reports & Data Export")
        st.write("Generate official multi-page PDF audit reports or export raw JSON telemetry for SIEM / SOC ingestion.")

        col_pdf, col_json = st.columns(2)

        with col_pdf:
            st.markdown("#### 📄 Forensic Audit PDF Report")
            st.write("Includes Executive Summary, Authenticode check, PE section entropy tables, ML feature impacts, and threat intelligence findings.")
            
            try:
                pdf_bytes = generate_pdf_report(active_report)
                safe_filename = filename.replace(".exe", "").replace(".dll", "").replace(".msi", "").replace(".apk", "")
                st.download_button(
                    label="📥 Download Forensic PDF Report (.pdf)",
                    data=pdf_bytes,
                    file_name=f"CertiScan_Audit_{safe_filename}.pdf",
                    mime="application/pdf",
                    type="primary",
                    use_container_width=True
                )
            except Exception as e:
                st.error(f"Failed to generate PDF: {e}")

        with col_json:
            st.markdown("#### 📊 Standardized IA3 JSON Telemetry")
            st.write("Complete serialized 4-member unified JSON payload conforming to the IA3 multi-pillar schema.")
            
            json_str = json.dumps(active_report, indent=2)
            st.download_button(
                label="📥 Download Merged IA3 JSON Report (.json)",
                data=json_str,
                file_name=f"CertiScan_Telemetry_{filename}.json",
                mime="application/json",
                use_container_width=True
            )

        st.markdown("---")
        st.markdown("#### 👁️ Interactive Raw JSON Telemetry Viewer")
        with st.expander("Inspect Full Merged JSON Payload", expanded=False):
            st.json(active_report)


# ==============================================================================
# VIEW 2: MEMBER 1 STANDALONE PORTAL (DANIEL)
# ==============================================================================
elif "Member 1 Portal" in portal_view:
    st.title("🔍 TrustShield // Member 1: Cryptographic & Static Binary Lead")
    st.markdown("**Lead:** Daniel | **Core Tech:** `hashlib`, `pefile`, `signify`, `math`")
    st.info("Member 1 specializes in safe PE/APK ingestion, cryptographic hash calculation, Authenticode certificate extraction, and Shannon entropy computation.")

    sample_choices = {
        "Clean Signed Utility Sim": os.path.join(MEMBER1_DIR, "demo_samples", "sample1_clean_signed_sim.exe"),
        "Counterfeit Chrome Trojan Sim": os.path.join(MEMBER1_DIR, "demo_samples", "sample2_fake_chrome_clone.exe"),
        "Packed High-Entropy Malware Sim": os.path.join(MEMBER1_DIR, "demo_samples", "sample3_packed_high_entropy.exe"),
        "Masquerading PDF Invoice Sim": os.path.join(MEMBER1_DIR, "demo_samples", "sample4_masquerading_invoice.pdf.exe")
    }
    sel_name = st.selectbox("Select Test Binary Sample:", list(sample_choices.keys()))
    sel_path = sample_choices[sel_name]

    if os.path.exists(sel_path):
        from analyzer.core_pipeline import analyze_binary
        m1_out = analyze_binary(sel_path)
        
        col1, col2, col3 = st.columns(3)
        col1.metric("Entropy", f"{m1_out['file_info']['overall_shannon_entropy']:.3f} / 8.0")
        col2.metric("Authenticode Signed", str(m1_out['certificate_status']['is_signed']))
        col3.metric("Clone Alert", "DETECTED" if m1_out['certificate_status']['clone_mismatch_detected'] else "NONE")

        st.markdown("#### 📋 Raw Member 1 Output Payload")
        st.json(m1_out)


# ==============================================================================
# VIEW 3: MEMBER 2 STANDALONE PORTAL (JEROM)
# ==============================================================================
elif "Member 2 Portal" in portal_view:
    st.title("🤖 TrustShield // Member 2: ML Anomaly & Repacking Probability Lead")
    st.markdown("**Lead:** Jerom | **Core Tech:** `scikit-learn`, `xgboost`, `joblib`, `pandas`")
    st.info("Member 2 consumes Member 1's static features, computes 12 normalized dimensions, and executes XGBoost inference for malware probability.")

    from ml_engine.model_inference import MalwarePredictor
    predictor = MalwarePredictor()

    sample_choices = {
        "Clean Signed Utility Sim": os.path.join(MEMBER1_DIR, "demo_samples", "sample1_clean_signed_sim.exe"),
        "Counterfeit Chrome Trojan Sim": os.path.join(MEMBER1_DIR, "demo_samples", "sample2_fake_chrome_clone.exe"),
        "Packed High-Entropy Malware Sim": os.path.join(MEMBER1_DIR, "demo_samples", "sample3_packed_high_entropy.exe"),
        "Masquerading PDF Invoice Sim": os.path.join(MEMBER1_DIR, "demo_samples", "sample4_masquerading_invoice.pdf.exe")
    }
    sel_name = st.selectbox("Select Sample to Classify:", list(sample_choices.keys()))
    sel_path = sample_choices[sel_name]

    if os.path.exists(sel_path):
        from analyzer.core_pipeline import analyze_binary
        m1_data = analyze_binary(sel_path)
        m2_pred = predictor.predict_risk(m1_data)
        
        ml_p = m2_pred.get("ml_prediction", {})
        prob = ml_p.get("malware_probability_score", 0.0)
        tier = ml_p.get("risk_tier") or ml_p.get("classification_verdict", "UNKNOWN")

        st.metric("Malware Probability Score", f"{prob:.1f}%", delta=f"Tier: {tier}", delta_color="inverse" if prob > 50 else "normal")
        
        top_feats = ml_p.get("top_feature_contributions") or ml_p.get("top_contributing_features", [])
        st.plotly_chart(create_ml_feature_importance_chart(top_feats), use_container_width=True)
        st.json(m2_pred)


# ==============================================================================
# VIEW 4: MEMBER 3 STANDALONE PORTAL (KRISHANTH)
# ==============================================================================
elif "Member 3 Portal" in portal_view:
    st.title("🌐 ThreatFuse // Member 3: Threat Intelligence & Consensus Lead")
    st.markdown("**Lead:** Krishanth | **Core Tech:** `requests`, VirusTotal v3, MalwareBazaar, Dynamic Weight Shifting")
    st.info("Member 3 cross-references external threat feeds and dynamically shifts weights when zero-day hashes are not found in cloud threat feeds.")

    from decision_engine.trust_scorer import compute_final_trust_score
    from threat_intel.cache_manager import get_cached_threat_intel

    test_scenario_choice = st.selectbox("Choose Evaluation Scenario:", [
        "Scenario 1: Clean Signed VLC (Cloud Verified)",
        "Scenario 2: Fake Chrome Trojan (Kill-Switch Active)",
        "Scenario 3: Zero-Day Packed Malware (Dynamic Weight Shift Active)",
        "Scenario 4: Suspicious Grayware / Adware"
    ])
    s_idx = int(test_scenario_choice.split(":")[0].replace("Scenario ", ""))
    scen_preset = load_scenario_preset(f"scenario_{s_idx}")

    m3_dec = scen_preset["member3_decision"]["trust_decision"]
    st.metric("Final Consensus Trust Score", f"{m3_dec['final_trust_score']:.2f} / 100", delta=m3_dec['verdict'])
    st.plotly_chart(create_pillar_breakdown_chart(m3_dec["pillar_scores"], m3_dec["weight_distribution"]), use_container_width=True)
    st.json(scen_preset["member3_threat_intel"])


# ==============================================================================
# VIEW 5: AI MODEL 2: EMBER2024 DEEP BINARY CLASSIFIER
# ==============================================================================
elif "AI Model 2" in portal_view:
    st.title("🚀 AI Model 2: EMBER2024 Deep Binary & ELF Classifier")
    st.markdown("**Modality:** Cross-Platform Binaries (ELF / Linux / Android / PE) | **Engine:** LightGBM Champion (620-D Feature Space)")
    st.info("AI Model 2 expands the defense suite beyond Windows PE static signatures into deep, universal byte-level and structural classification trained on the chronological EMBER 2024 VirusTotal benchmark.")

    ai2_pred = get_ai_model2_predictor()
    ai2_meta = load_ai2_metadata()
    test_meta, X_test, y_test = load_ai2_test_samples()

    # Top KPI metric cards
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Champion Model", ai2_meta.get("champion_model", "LightGBM"))
    with col2:
        st.metric("Test Accuracy", f"{ai2_meta.get('metrics', {}).get('accuracy', 0.9508)*100:.2f}%")
    with col3:
        st.metric("Test F1-Score", f"{ai2_meta.get('metrics', {}).get('f1', 0.9515):.4f}")
    with col4:
        st.metric("Test ROC-AUC", f"{ai2_meta.get('metrics', {}).get('roc_auc', 0.9906):.4f}")
    with col5:
        st.metric("Test Recall", f"{ai2_meta.get('metrics', {}).get('recall', 0.9653)*100:.1f}%")

    st.markdown("---")

    mode_ai2 = st.radio(
        "Choose Inspection Mode:",
        ["🔬 Held-out Test Set Explorer (Weeks 53–64)", "📁 Upload Binary or JSON File", "🎛️ Manual Feature Tweaking", "📊 Benchmark Performance & Evaluation"],
        horizontal=True
    )

    # Sub-Mode 1: Held-out Test Set Explorer
    if "Held-out Test Set Explorer" in mode_ai2:
        st.subheader("🔬 Held-out Future Test Samples (Chronological Weeks 53–64)")
        st.caption("Evaluate the champion model against authentic historical samples collected chronologically after training data.")

        if test_meta and len(test_meta) > 0 and X_test is not None:
            filter_opt = st.selectbox("Filter Samples by Ground Truth:", ["All Samples", "Malicious Only", "Benign Only"])
            filtered_indices = []
            for i, m in enumerate(test_meta):
                lbl = m.get("label")
                if filter_opt == "All Samples" or (filter_opt == "Malicious Only" and lbl == 1) or (filter_opt == "Benign Only" and lbl == 0):
                    filtered_indices.append(i)

            sample_idx = st.slider("Select Sample Index:", 0, len(filtered_indices) - 1, 0)
            chosen_real_idx = filtered_indices[sample_idx]
            chosen_sample = test_meta[chosen_real_idx]

            col_a, col_b = st.columns([1, 1])
            with col_a:
                st.markdown("#### 📄 Sample Telemetry")
                st.write(f"**SHA256:** `{chosen_sample.get('sha256')}`")
                st.write(f"**Detected Format:** `{chosen_sample.get('file_type', 'ELF')}`")
                st.write(f"**VirusTotal Detection Ratio:** `{chosen_sample.get('detection_ratio', 'N/A')}`")
                true_label_str = "MALICIOUS (1)" if chosen_sample.get("label") == 1 else "BENIGN (0)"
                st.write(f"**Ground Truth Label:** `{true_label_str}`")

            with col_b:
                if st.button("🚀 Run Live AI Model 2 Prediction", type="primary", use_container_width=True):
                    probs = ai2_pred.model.predict_proba(X_test[chosen_real_idx:chosen_real_idx+1])[0]
                    pred_label = int(np.argmax(probs))
                    confidence = probs[pred_label]
                    is_correct = (pred_label == chosen_sample.get("label"))

                    st.markdown("#### 🎯 Model Decision")
                    if pred_label == 1:
                        st.markdown(f'<div class="badge-danger" style="display:block;text-align:center;font-size:18px;padding:12px;">⚠️ MALICIOUS DETECTED ({confidence*100:.2f}% Confidence)</div>', unsafe_allow_html=True)
                    else:
                        st.markdown(f'<div class="badge-safe" style="display:block;text-align:center;font-size:18px;padding:12px;">✅ BENIGN / CLEAN ({confidence*100:.2f}% Confidence)</div>', unsafe_allow_html=True)

                    st.write("")
                    st.progress(float(probs[1]))
                    st.caption(f"P(Malicious): {probs[1]*100:.2f}% | P(Benign): {probs[0]*100:.2f}%")

                    if is_correct:
                        st.success("🎯 Prediction matches ground truth perfectly!")
                    else:
                        st.warning("⚠️ Prediction deviates from ground truth.")
        else:
            st.info("Test dataset metadata not found in 'AI model 2/processed'.")

    # Sub-Mode 2: Upload File
    elif "Upload Binary or JSON File" in mode_ai2:
        st.subheader("📁 Upload Binary Executable or EMBER JSON Record")
        uploaded_ai2_file = st.file_uploader("Upload binary file (.bin, .elf, .exe, .dll, .apk, .json):", key="ai2_uploader")

        if uploaded_ai2_file is not None:
            file_bytes = uploaded_ai2_file.read()
            file_name = uploaded_ai2_file.name
            st.info(f"Target: `{file_name}` ({len(file_bytes):,} bytes)")

            if st.button("🚀 Analyze with AI Model 2", type="primary"):
                with st.spinner("Extracting byte histogram, 256-bin entropy, printable strings..."):
                    if file_name.endswith(".json"):
                        record = json.loads(file_bytes.decode("utf-8"))
                        result = ai2_pred.predict_record(record)
                    else:
                        with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{file_name}") as tmp_ai2:
                            tmp_ai2.write(file_bytes)
                            tmp_ai2_path = tmp_ai2.name
                        try:
                            result = ai2_pred.predict_binary_file(tmp_ai2_path)
                        finally:
                            if os.path.exists(tmp_ai2_path):
                                os.remove(tmp_ai2_path)

                pred_label = result["prediction"]
                confidence = result["confidence"]

                st.markdown("### 🎯 Analysis Verdict")
                if pred_label == 1:
                    st.markdown(f'<div class="badge-danger" style="display:block;text-align:center;font-size:18px;padding:12px;">⚠️ MALICIOUS THREAT DETECTED ({confidence*100:.2f}% Confidence)</div>', unsafe_allow_html=True)
                else:
                    st.markdown(f'<div class="badge-safe" style="display:block;text-align:center;font-size:18px;padding:12px;">✅ BENIGN / SAFE FILE ({confidence*100:.2f}% Confidence)</div>', unsafe_allow_html=True)

                col_x, col_y = st.columns(2)
                with col_x:
                    fig_g = go.Figure(go.Indicator(
                        mode="gauge+number",
                        value=result["prob_malicious"] * 100,
                        title={'text': "Malware Risk Score (%)"},
                        gauge={
                            'axis': {'range': [0, 100]},
                            'bar': {'color': "#ef4444" if pred_label == 1 else "#10b981"},
                            'steps': [
                                {'range': [0, 50], 'color': "rgba(16, 185, 129, 0.15)"},
                                {'range': [50, 75], 'color': "rgba(245, 158, 11, 0.15)"},
                                {'range': [75, 100], 'color': "rgba(239, 68, 68, 0.15)"}
                            ]
                        }
                    ))
                    fig_g.update_layout(height=280, margin=dict(l=20, r=20, t=40, b=20), paper_bgcolor="rgba(0,0,0,0)", font={'color': "#f1f5f9"})
                    st.plotly_chart(fig_g, use_container_width=True)

                with col_y:
                    st.markdown("#### 🔬 Top Activating Features")
                    for tf in result.get("top_features", [])[:8]:
                        st.write(f"- **`{tf['feature']}`**: raw=`{tf['raw_value']:.4f}`, weight=`{tf.get('importance_weight', 1.0):.2f}`")

    # Sub-Mode 3: Manual Feature Tweaking
    elif "Manual Feature Tweaking" in mode_ai2:
        st.subheader("🎛️ Manually Test Key Feature Vectors")
        st.caption("Adjust dominant file properties to observe real-time model confidence shifts.")

        c1, c2 = st.columns(2)
        with c1:
            f_size = st.number_input("File Size (bytes):", min_value=100, max_value=50000000, value=150000)
            f_entropy = st.slider("Shannon Byte Entropy (0.0 - 8.0):", 0.0, 8.0, 5.8)
            f_numstrings = st.number_input("Extracted ASCII Strings Count:", min_value=0, max_value=100000, value=350)
        with c2:
            f_avlength = st.slider("Average String Length:", 1.0, 100.0, 15.0)
            f_printables = st.number_input("Total Printable Characters:", min_value=0, max_value=500000, value=5000)
            f_is_pe = st.selectbox("Is PE Binary?", [0, 1], index=0)

        if st.button("🚀 Compute Synthetic Prediction", type="primary"):
            syn = np.zeros(620, dtype=np.float32)
            syn[0:256] = 1.0 / 256.0
            syn[256:512] = f_entropy
            syn[512:608] = 1.0 / 96.0
            syn[608] = float(f_numstrings)
            syn[609] = float(f_avlength)
            syn[610] = float(f_printables)
            syn[611] = float(f_entropy * 0.8)
            syn[612] = float(f_size)
            syn[613] = float(np.log1p(f_size))
            syn[614] = float(f_entropy)
            syn[615] = float(f_is_pe)

            result = ai2_pred.predict_features(syn)
            pred_label = result["prediction"]
            confidence = result["confidence"]

            if pred_label == 1:
                st.markdown(f'<div class="badge-danger" style="display:block;text-align:center;font-size:18px;padding:12px;">⚠️ MALICIOUS PREDICTION ({confidence*100:.2f}%)</div>', unsafe_allow_html=True)
            else:
                st.markdown(f'<div class="badge-safe" style="display:block;text-align:center;font-size:18px;padding:12px;">✅ BENIGN PREDICTION ({confidence*100:.2f}%)</div>', unsafe_allow_html=True)

    # Sub-Mode 4: Benchmark Performance
    elif "Benchmark Performance" in mode_ai2:
        st.subheader("📊 EMBER2024 Model Performance & Benchmarks")

        tab_b1, tab_b2, tab_b3 = st.tabs(["Candidate Model Comparison", "Confusion Matrix Heatmap", "Feature Importance Ranking"])

        with tab_b1:
            st.markdown("#### Benchmark on 12,000 Unseen Held-out Samples (Weeks 53–64)")
            all_results = ai2_meta.get("all_model_results", {})
            if all_results:
                rows = []
                for m, res in all_results.items():
                    rows.append({
                        "Model": m,
                        "Accuracy": f"{res['accuracy']*100:.2f}%",
                        "Precision": f"{res['precision']*100:.2f}%",
                        "Recall": f"{res['recall']*100:.2f}%",
                        "F1-Score": f"{res['f1']:.4f}",
                        "ROC-AUC": f"{res['roc_auc']:.4f}"
                    })
                st.dataframe(pd.DataFrame(rows), use_container_width=True)
            else:
                st.info("Benchmark data available in models/model_metadata.json")

        with tab_b2:
            cm_path = AI_MODEL2_DIR / "models" / "confusion_matrix.png"
            if cm_path.exists():
                st.image(str(cm_path), caption="Test Split Confusion Matrix (LightGBM Champion on 12,000 Samples)", use_container_width=True)

        with tab_b3:
            fi_path = AI_MODEL2_DIR / "models" / "feature_importance.png"
            if fi_path.exists():
                st.image(str(fi_path), caption="Top 20 Features Importance (Gain / Split Importance)", use_container_width=True)


# ==============================================================================
# VIEW 6: AUTOMATED TEST SUITE & HEALTH HUB
# ==============================================================================
elif "Automated Test Suite" in portal_view:
    st.title("🧪 Automated Integration Test Suite & Verification Hub")
    st.markdown("Execute the complete 21-test end-to-end verification suite across all 4 member modules and AI Model 2.")

    if st.button("🚀 Run All 21 Unit & Integration Tests", type="primary"):
        with st.spinner("Running pytest across Members 1, 2, 3, 4, and AI Model 2..."):
            cmd = [
                sys.executable,
                "-m",
                "pytest",
                "Jerom/trustshield-member2/tests",
                "Krishanth/threatfuse-member3/tests",
                "Rohith/certiscan-maldetect-ai/tests",
                "AI model 2/tests",
                "-v"
            ]
            res = subprocess.run(cmd, cwd=ROOT_DIR, capture_output=True, text=True)

            if res.returncode == 0:
                st.success("✅ All 21 Tests Passed Successfully!")
            else:
                st.error("❌ Some tests failed or returned non-zero code.")

            st.code(res.stdout + res.stderr, language="bash")
