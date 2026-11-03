"""
CertiScan Studio // MalDetect-AI
Member 4: Frontend UI & Full System Integration Lead
Master Streamlit Web Application integrating Member 1, Member 2, and Member 3.
"""

import os
import sys
import json
import time
import tempfile
import pandas as pd
import streamlit as st

# Configure sys.path
APP_DIR = os.path.dirname(os.path.abspath(__file__))
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

from integration.pipeline_orchestrator import run_full_security_pipeline, load_scenario_preset
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
    page_title="CertiScan Studio // MalDetect-AI",
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

    /* Status badge pill */
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
# SIDEBAR CONTROLS
# ==============================================================================
with st.sidebar:
    st.markdown("""
    <div style="text-align:center;padding:10px 0 20px 0;">
        <div style="font-size:28px;font-weight:900;letter-spacing:-1px;color:#f8fafc;">
            🛡️ <span style="color:#38bdf8;">CERTISCAN</span> STUDIO
        </div>
        <div style="font-size:12px;color:#94a3b8;font-weight:600;letter-spacing:1px;text-transform:uppercase;">
            MalDetect-AI Defense-in-Depth
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("### 🎛️ Analysis Source")
    analysis_mode = st.radio(
        "Select Operation Mode:",
        ["🎯 Load Pre-Verified Demo Scenario", "📂 Upload Live File (.exe, .dll, .msi, .apk)"],
        index=0
    )

    active_report = None

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
        except Exception as e:
            st.error(f"Error loading demo scenario: {e}")

    else:
        uploaded_file = st.file_uploader(
            "Upload Executable Binary:",
            type=["exe", "dll", "msi", "apk", "sys", "bin"],
            help="Upload any Windows PE32 / PE32+ executable, MSI, or APK package for multi-pillar analysis"
        )

        with st.expander("🔑 Threat Intelligence Settings & API Keys", expanded=False):
            vt_key = st.text_input("VirusTotal API Key (v3)", type="password", help="Leave blank to use local offline cache")
            mb_key = st.text_input("MalwareBazaar Auth Key", type="password", help="Leave blank to use local offline cache")
            force_offline_cache = st.checkbox("Force Offline TI Cache Only", value=True, help="Use pre-cached responses without hitting live rate limits")

        if uploaded_file is not None:
            if st.button("🚀 Run 4-Stage Analysis Pipeline", type="primary", use_container_width=True):
                with st.status("Executing 4-Stage Defense-in-Depth Pipeline...", expanded=True) as status:
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
                        
                        st.write("📑 **Stage 4 (Member 4)**: Assembling Security Nutrition Label, Plotly Analytics & Forensic Report...")
                        time.sleep(0.2)
                        
                        # Set uploaded filename
                        live_rep["member1_static"]["file_info"]["filename"] = uploaded_file.name
                        live_rep["metadata"]["analyzed_file"] = uploaded_file.name
                        
                        st.session_state["live_analysis_report"] = live_rep
                        st.session_state["live_analysis_filename"] = uploaded_file.name
                        status.update(label="✅ 4-Stage Security Pipeline Complete!", state="complete", expanded=False)
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
        <b>IA3 Research Team:</b><br>
        • <b>Daniel:</b> Member 1 (Crypto & Static Binary Lead)<br>
        • <b>Jerom:</b> Member 2 (ML Anomaly & Repacking Lead)<br>
        • <b>Krishanth:</b> Member 3 (Threat Intel & Decision Lead)<br>
        • <b>Rohith:</b> Member 4 (Frontend UI & Orchestrator Lead)<br>
        <div style="margin-top:6px;color:#38bdf8;font-weight:600;">CertiScan Engine v1.0.0</div>
    </div>
    """, unsafe_allow_html=True)


# ==============================================================================
# MAIN DASHBOARD CONTENT
# ==============================================================================
if active_report is None:
    st.title("🛡️ CertiScan Studio // MalDetect-AI Unified Dashboard")
    st.info("👈 Please select a Demo Scenario or upload a binary from the sidebar to begin analysis.")
    st.stop()

# Extract Data Sections
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


# ------------------------------------------------------------------------------
# TOP EXECUTIVE SUMMARY ROW: Left = Plotly Gauge & Verdict | Right = Nutrition Label
# ------------------------------------------------------------------------------
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


# ==============================================================================
# 4 ORGANIZED DEEP-DIVE TABS
# ==============================================================================
tab1, tab2, tab3, tab4 = st.tabs([
    "📋 Tab 1: Executive Risk & Clone Diff Inspector",
    "🔍 Tab 2: Static Binary & Crypto Forensics (Member 1)",
    "🤖 Tab 3: AI/ML & Cloud Threat Intel (Members 2 & 3)",
    "📑 Tab 4: PDF Audit Report & Raw JSON Export (Member 4)"
])


# ------------------------------------------------------------------------------
# TAB 1: EXECUTIVE RISK & CLONE DIFF INSPECTOR
# ------------------------------------------------------------------------------
with tab1:
    # Critical Kill-Switch Overrides Alert (if triggered)
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


# ------------------------------------------------------------------------------
# TAB 2: STATIC BINARY & CRYPTO FORENSICS (MEMBER 1)
# ------------------------------------------------------------------------------
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


# ------------------------------------------------------------------------------
# TAB 3: AI/ML & THREAT INTEL (MEMBERS 2 & 3)
# ------------------------------------------------------------------------------
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


# ------------------------------------------------------------------------------
# TAB 4: FORENSIC REPORTS & EXPORTS (MEMBER 4)
# ------------------------------------------------------------------------------
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
