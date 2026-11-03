"""
TrustShield: Pre-Install Software Authenticity & Counterfeit Clone Detector
Member 1: Cryptographic & Static Binary Analysis Engine + Interactive Dashboard
"""

import os
import sys
import json
import tempfile
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

# Configure page settings
st.set_page_config(
    page_title="TrustShield | Software Nutrition Label & Static Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Ensure local imports
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from analyzer.core_pipeline import analyze_binary

# Custom CSS for rich cybersecurity aesthetics and the Software Nutrition Label
CUSTOM_CSS = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;800&family=Plus+Jakarta+Sans:wght@400;600;700;800&display=swap');

    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    code, pre, .mono {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Main Container glow */
    .main .block-container {
        padding-top: 2rem;
        padding-bottom: 3rem;
        max-width: 1400px;
    }

    /* Software Nutrition Label Card */
    .nutrition-card {
        background: #0d1117;
        border: 2px solid #30363d;
        border-radius: 12px;
        padding: 24px;
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.4);
        margin-bottom: 24px;
        position: relative;
        overflow: hidden;
    }

    .nutrition-header {
        border-bottom: 8px solid #f0f6fc;
        padding-bottom: 8px;
        margin-bottom: 12px;
    }

    .nutrition-title {
        font-size: 28px;
        font-weight: 800;
        letter-spacing: -0.5px;
        color: #f0f6fc;
        margin: 0;
        text-transform: uppercase;
    }

    .nutrition-subtitle {
        font-size: 13px;
        color: #8b949e;
        margin-top: 2px;
    }

    .nutrition-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 8px 0;
        border-bottom: 1px solid #21262d;
        font-size: 14px;
    }

    .nutrition-row.bold {
        font-weight: 700;
        border-bottom: 2px solid #30363d;
    }

    .nutrition-row.danger {
        color: #ff7b72;
    }

    .nutrition-row.warning {
        color: #d29922;
    }

    .nutrition-row.safe {
        color: #3fb950;
    }

    /* Verdict Badges */
    .badge-safe {
        background: rgba(46, 160, 67, 0.15);
        color: #3fb950;
        border: 1px solid rgba(46, 160, 67, 0.4);
        padding: 6px 14px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 13px;
        display: inline-block;
    }

    .badge-suspicious {
        background: rgba(210, 153, 34, 0.15);
        color: #d29922;
        border: 1px solid rgba(210, 153, 34, 0.4);
        padding: 6px 14px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 13px;
        display: inline-block;
    }

    .badge-danger {
        background: rgba(248, 81, 73, 0.15);
        color: #ff7b72;
        border: 1px solid rgba(248, 81, 73, 0.4);
        padding: 6px 14px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 13px;
        display: inline-block;
        animation: pulse 2s infinite;
    }

    @keyframes pulse {
        0% { box-shadow: 0 0 0 0 rgba(248, 81, 73, 0.4); }
        70% { box-shadow: 0 0 0 8px rgba(248, 81, 73, 0); }
        100% { box-shadow: 0 0 0 0 rgba(248, 81, 73, 0); }
    }

    /* Metric card */
    .metric-box {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 10px;
        padding: 16px;
        text-align: center;
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .metric-box:hover {
        border-color: #58a6ff;
        transform: translateY(-2px);
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# Application Header
col_hdr_l, col_hdr_r = st.columns([3, 1])
with col_hdr_l:
    st.markdown("## 🛡️ TrustShield — Counterfeit & Malware Verification")
    st.markdown(
        "**IA3 Member 1 Deliverable**: Cryptographic Hashing, Authenticode Verification, PE/APK Metadata Extraction & Shannon Entropy Engine"
    )
with col_hdr_r:
    st.markdown(
        """
        <div style="text-align: right; padding-top: 10px;">
            <span style="background: #238636; color: white; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 700;">ENGINE ACTIVE</span>
            <div style="color: #8b949e; font-size: 11px; margin-top: 4px;">Standard IA3 JSON v1.0</div>
        </div>
        """,
        unsafe_allow_html=True
    )

st.markdown("---")

# Sidebar for Sample Selection & Uploads
with st.sidebar:
    st.markdown("### 🔍 Binary Target Input")
    input_mode = st.radio("Select Ingestion Method:", ["Preset Safe Demo Samples", "Upload Local Binary (.exe, .dll, .apk)"])

    sample_map = {
        "1. Clean Utility (1_clean_utility_sim.exe - Normal entropy ~5.6, clean headers)": "1_clean_utility_sim.exe",
        "2. Fake Chrome Installer (2_fake_chrome_installer.exe - Counterfeit clone alert)": "2_fake_chrome_installer.exe",
        "3. Packed Malware Simulation (3_packed_malware_sim.exe - High entropy >7.9, UPX0, W+X)": "3_packed_malware_sim.exe",
        "4. Masquerading Document (4_masquerading_document.pdf - MZ executable disguised as PDF)": "4_masquerading_document.pdf",
        "Sample 1 (Alias): sample1_clean_signed_sim.exe": "sample1_clean_signed_sim.exe",
        "Sample 2 (Alias): sample2_fake_chrome_clone.exe": "sample2_fake_chrome_clone.exe",
        "Sample 3 (Alias): sample3_packed_high_entropy.exe": "sample3_packed_high_entropy.exe",
        "Sample 4 (Alias): sample4_masquerading_invoice.pdf.exe": "sample4_masquerading_invoice.pdf.exe"
    }

    target_filepath = None
    target_filename = None

    if input_mode == "Preset Safe Demo Samples":
        selected_label = st.selectbox("Choose Demo Test Binaries:", list(sample_map.keys()))
        rel_filename = sample_map[selected_label]
        target_filename = rel_filename

        # Look in demo_samples relative to app.py
        candidate_path = os.path.join(CURRENT_DIR, "demo_samples", rel_filename)
        if os.path.exists(candidate_path):
            target_filepath = candidate_path
        else:
            # Try running generator script if missing
            from scripts.generate_demo_samples import generate_samples
            generate_samples(os.path.join(CURRENT_DIR, "demo_samples"))
            target_filepath = candidate_path

        st.info(f"Target selected: `{rel_filename}`")

    else:
        uploaded_file = st.file_uploader(
            "Upload executable binary or APK:",
            type=["exe", "dll", "msi", "sys", "apk", "bin", "pdf"]
        )
        if uploaded_file is not None:
            # Save safely to temp file
            t_dir = tempfile.gettempdir()
            target_filepath = os.path.join(t_dir, uploaded_file.name)
            target_filename = uploaded_file.name
            with open(target_filepath, "wb") as f:
                f.write(uploaded_file.getbuffer())
            st.success(f"Uploaded: `{uploaded_file.name}` ({len(uploaded_file.getbuffer()):,} bytes)")

    st.markdown("---")
    st.markdown("#### ⚙️ Engine Settings")
    st.markdown("- **Entropy Threshold**: `7.2000`")
    st.markdown("- **Hashpass**: MD5 + SHA-1 + SHA-256")
    st.markdown("- **Authenticode Engine**: `Signify v0.9`")
    st.markdown("- **Threat Feed**: `known_bad_hashes.json`")

# Analysis execution
if target_filepath and os.path.exists(target_filepath):
    try:
        with st.spinner(f"Performing deep static binary analysis on {target_filename}..."):
            report = analyze_binary(target_filepath)
    except Exception as e:
        st.error(f"Analysis error: {e}")
        st.stop()

    file_info = report["file_info"]
    hashes = report["hashes"]
    cert = report["certificate_status"]
    pe_meta = report["pe_metadata"]
    risk = report["risk_assessment"]
    score = risk["risk_score"]
    verdict = risk["verdict"]
    reasons = risk["reasons"]

    # Top Row: KPI Badges & Security Nutrition Summary
    kpi_col1, kpi_col2, kpi_col3, kpi_col4 = st.columns(4)

    with kpi_col1:
        st.markdown(
            f"""
            <div class="metric-box">
                <div style="color: #8b949e; font-size: 12px; font-weight: 600; text-transform: uppercase;">VERDICT</div>
                <div style="margin-top: 6px;">
                    <span class="{'badge-safe' if verdict == 'SAFE' else 'badge-suspicious' if verdict == 'SUSPICIOUS' else 'badge-danger'}">
                        {verdict}
                    </span>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with kpi_col2:
        score_color = "#3fb950" if score <= 25 else "#d29922" if score <= 65 else "#ff7b72"
        st.markdown(
            f"""
            <div class="metric-box">
                <div style="color: #8b949e; font-size: 12px; font-weight: 600; text-transform: uppercase;">RISK SCORE</div>
                <div style="font-size: 26px; font-weight: 800; color: {score_color}; margin-top: 2px;">
                    {score} <span style="font-size: 14px; color: #8b949e; font-weight: 400;">/ 100</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with kpi_col3:
        clone_flag = cert.get("clone_mismatch_detected", False)
        clone_color = "#ff7b72" if clone_flag else "#3fb950"
        clone_text = "MISMATCH DETECTED" if clone_flag else "NO MISMATCH"
        st.markdown(
            f"""
            <div class="metric-box">
                <div style="color: #8b949e; font-size: 12px; font-weight: 600; text-transform: uppercase;">CLONE IDENTIFIER</div>
                <div style="font-size: 16px; font-weight: 700; color: {clone_color}; margin-top: 8px;">
                    {'⚠️ ' + clone_text if clone_flag else '🛡️ ' + clone_text}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with kpi_col4:
        entropy_val = file_info.get("overall_shannon_entropy", 0.0)
        ent_color = "#ff7b72" if entropy_val > 7.2 else "#d29922" if entropy_val > 6.5 else "#3fb950"
        st.markdown(
            f"""
            <div class="metric-box">
                <div style="color: #8b949e; font-size: 12px; font-weight: 600; text-transform: uppercase;">OVERALL ENTROPY</div>
                <div style="font-size: 24px; font-weight: 800; color: {ent_color}; margin-top: 2px;">
                    {entropy_val:.4f} <span style="font-size: 12px; color: #8b949e; font-weight: 400;">/ 8.0</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("<br>", unsafe_allow_html=True)

    # Main Grid: Left Column = Nutrition Label Card; Right Column = Gauges & Heuristics
    card_col, chart_col = st.columns([1.2, 1.8])

    with card_col:
        # Software Nutrition Label HTML
        mismatch_html = (
            f"<div class='nutrition-row danger bold'><span>⚠️ CLONE MISMATCH</span><span>DETECTED</span></div>"
            if cert.get("clone_mismatch_detected")
            else "<div class='nutrition-row safe'><span>Publisher Spoof Check</span><span>Clean</span></div>"
        )

        masquerade_html = (
            f"<div class='nutrition-row danger bold'><span>⚠️ MASQUERADING</span><span>DOUBLE EXTENSION</span></div>"
            if file_info.get("extension_masquerading")
            else "<div class='nutrition-row safe'><span>Extension Integrity</span><span>Matched</span></div>"
        )

        wx_html = (
            f"<div class='nutrition-row danger bold'><span>⚠️ W+X PERMISSIONS</span><span>CRITICAL RISK</span></div>"
            if any(s.get("wx_risk") for s in pe_meta.get("sections", []))
            else "<div class='nutrition-row safe'><span>Memory Page NX/DEP</span><span>Enforced</span></div>"
        )

        packing_html = (
            f"<div class='nutrition-row warning bold'><span>Packing Indicator</span><span>HIGH ENTROPY</span></div>"
            if file_info.get("is_likely_packed")
            else "<div class='nutrition-row safe'><span>Packing Indicator</span><span>None</span></div>"
        )

        st.markdown(
            f"""
            <div class="nutrition-card">
                <div class="nutrition-header">
                    <div class="nutrition-title">Software Nutrition Label</div>
                    <div class="nutrition-subtitle">Static Pre-Install Authenticity Specification</div>
                </div>
                <div class="nutrition-row bold">
                    <span>Target File</span>
                    <span class="mono" style="color: #58a6ff;">{file_info.get('filename')}</span>
                </div>
                <div class="nutrition-row">
                    <span>Detected Format</span>
                    <span>{file_info.get('detected_format')}</span>
                </div>
                <div class="nutrition-row">
                    <span>File Size</span>
                    <span>{file_info.get('size_bytes', 0):,} bytes</span>
                </div>
                <div class="nutrition-row">
                    <span>Magic Bytes</span>
                    <span class="mono">{file_info.get('magic_bytes')}</span>
                </div>
                <div class="nutrition-row bold" style="border-top: 4px solid #f0f6fc; margin-top: 8px;">
                    <span>Calculated Threat Index</span>
                    <span style="font-size: 18px; color: {score_color};">{score} / 100</span>
                </div>
                {mismatch_html}
                {masquerade_html}
                {wx_html}
                {packing_html}
                <div class="nutrition-row">
                    <span>Digital Signature</span>
                    <span style="font-weight: 600;">{cert.get('verification_status')}</span>
                </div>
                <div class="nutrition-row">
                    <span>Signer Identity</span>
                    <span>{cert.get('signer_common_name') or 'None'}</span>
                </div>
                <div class="nutrition-row">
                    <span>Claimed Product</span>
                    <span>{cert.get('claimed_product_name') or 'N/A'}</span>
                </div>
                <div class="nutrition-row">
                    <span>Claimed Vendor</span>
                    <span>{cert.get('claimed_company_name') or 'N/A'}</span>
                </div>
                <div class="nutrition-row">
                    <span>PE Compile Timestamp</span>
                    <span class="mono">{pe_meta.get('compile_timestamp') or 'N/A'}</span>
                </div>
                <div class="nutrition-row bold" style="border-top: 4px solid #f0f6fc; margin-top: 8px;">
                    <span>Suspicious API Imports</span>
                    <span>{len(pe_meta.get('suspicious_imports', []))} detected</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with chart_col:
        # Gauge Chart for Shannon Entropy
        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=entropy_val,
            title={'text': "Shannon Entropy Gauge (H)", 'font': {'size': 18, 'color': '#f0f6fc'}},
            number={'valueformat': ".4f", 'font': {'color': '#f0f6fc', 'family': 'JetBrains Mono'}},
            domain={'x': [0, 1], 'y': [0, 1]},
            gauge={
                'axis': {'range': [0, 8], 'tickwidth': 1, 'tickcolor': "#8b949e", 'nticks': 9},
                'bar': {'color': "#58a6ff"},
                'bgcolor': "#161b22",
                'borderwidth': 2,
                'bordercolor': "#30363d",
                'steps': [
                    {'range': [0, 6.5], 'color': "rgba(63, 185, 80, 0.25)"},
                    {'range': [6.5, 7.2], 'color': "rgba(210, 153, 34, 0.25)"},
                    {'range': [7.2, 8.0], 'color': "rgba(248, 81, 73, 0.35)"}
                ],
                'threshold': {
                    'line': {'color': "#ff7b72", 'width': 4},
                    'thickness': 0.8,
                    'value': 7.2
                }
            }
        ))
        fig_gauge.update_layout(
            height=260,
            margin=dict(l=20, r=20, t=40, b=20),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)"
        )
        st.plotly_chart(fig_gauge, use_container_width=True)

        # Active Risk Indicators Callout
        st.markdown("#### 🚨 Active Heuristic Findings & Anomaly Log")
        if reasons:
            for r in reasons:
                if any(k in r.lower() for k in ["critical", "counterfeit", "process injection", "masquerading", "w+x"]):
                    st.error(f"**CRITICAL**: {r}")
                elif any(k in r.lower() for k in ["high", "packed", "tampering", "spoofing"]):
                    st.warning(f"**WARNING**: {r}")
                else:
                    st.info(f"**NOTE**: {r}")
        else:
            st.success("No anomalies or malicious indicators detected in static analysis.")

    st.markdown("---")

    # Detailed Inspection Tabs
    tab_sections, tab_apis, tab_hashes, tab_cert, tab_json = st.tabs([
        "📊 PE Sections & Entropy Chart",
        "⚡ Suspicious IAT APIs",
        "🔑 Cryptographic Hashes",
        "📜 Authenticode Certificate Chain",
        "📄 Raw IA3 JSON Report"
    ])

    # TAB 1: Sections & Bar Chart
    with tab_sections:
        sections = pe_meta.get("sections", [])
        if sections:
            sec_df = pd.DataFrame(sections)

            # Plotly Section Entropy Bar Chart
            bar_colors = [
                '#ff7b72' if row['entropy'] > 7.2 or row['wx_risk'] else '#3fb950' if row['entropy'] < 6.5 else '#d29922'
                for _, row in sec_df.iterrows()
            ]

            fig_bar = go.Figure(data=[
                go.Bar(
                    x=sec_df['name'],
                    y=sec_df['entropy'],
                    marker_color=bar_colors,
                    text=[f"{e:.4f}" for e in sec_df['entropy']],
                    textposition='auto',
                    hovertext=[
                        f"Section: {r['name']}<br>Virtual Size: {r['virtual_size']:,} bytes<br>Raw Size: {r['raw_size']:,} bytes<br>W+X: {r['wx_risk']}"
                        for _, r in sec_df.iterrows()
                    ]
                )
            ])
            # Add 7.2 threshold line
            fig_bar.add_shape(
                type="line",
                x0=-0.5,
                x1=len(sec_df) - 0.5,
                y0=7.2,
                y1=7.2,
                line=dict(color="#ff7b72", width=2, dash="dash")
            )
            fig_bar.add_annotation(
                x=len(sec_df) - 0.5,
                y=7.2,
                text="Packing / Encryption Threshold (7.2)",
                showarrow=False,
                yshift=10,
                font=dict(color="#ff7b72", size=12)
            )
            fig_bar.update_layout(
                title="Section-by-Section Shannon Entropy Distribution",
                yaxis=dict(title="Shannon Entropy (0.0 - 8.0)", range=[0, 8.5]),
                xaxis=dict(title="PE Section Name"),
                height=350,
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#f0f6fc")
            )
            st.plotly_chart(fig_bar, use_container_width=True)

            # Section Table
            st.markdown("##### Section Permission & Size Breakdown")
            display_df = sec_df.copy()
            display_df['wx_risk'] = display_df['wx_risk'].apply(lambda x: "⚠️ W+X ALERT" if x else "Safe (W^X)")
            st.dataframe(
                display_df.style.map(
                    lambda v: "color: #ff7b72; font-weight: bold;" if "ALERT" in str(v) else "",
                    subset=['wx_risk']
                ),
                use_container_width=True
            )
        else:
            st.info("No PE sections found (file may be an APK, non-PE binary, or stripped).")

    # TAB 2: Suspicious APIs
    with tab_apis:
        cat_apis = report.get("categorized_apis", {})
        if cat_apis:
            st.markdown("#### High-Risk Imported APIs Grouped by Attack Technique")
            for cat_name, cat_data in cat_apis.items():
                sev = cat_data.get("severity", "MEDIUM")
                sev_color = "#ff7b72" if sev == "CRITICAL" else "#d29922" if sev == "HIGH" else "#58a6ff"
                with st.expander(f"🔴 {cat_name} — Severity: {sev} ({cat_data.get('mitre_technique')})", expanded=True):
                    st.markdown(f"**Threat Description**: {cat_data.get('description')}")
                    st.markdown("**Matched APIs Found in Binary IAT**:")
                    st.write(", ".join([f"`{api}`" for api in cat_data.get("matched_apis", [])]))
        else:
            st.success("No dangerous API patterns or process injection combinations detected in the Import Address Table.")

    # TAB 3: Hashes
    with tab_hashes:
        st.markdown("#### Cryptographic Fingerprints")
        h_col1, h_col2 = st.columns(2)
        with h_col1:
            st.text_input("MD5 Digest", value=hashes.get("md5", ""), disabled=True)
            st.text_input("SHA-1 Digest", value=hashes.get("sha1", ""), disabled=True)
        with h_col2:
            st.text_input("SHA-256 Digest", value=hashes.get("sha256", ""), disabled=True)
            st.text_input("Import Table Hash (Imphash)", value=hashes.get("imphash", ""), disabled=True)

    # TAB 4: Certificate
    with tab_cert:
        st.markdown("#### Authenticode Digital Signature Status")
        c1, c2 = st.columns(2)
        with c1:
            st.markdown(f"- **Signature Embedded**: `{cert.get('is_signed')}`")
            st.markdown(f"- **Verification Status**: `{cert.get('verification_status')}`")
            st.markdown(f"- **Signer Common Name (CN)**: `{cert.get('signer_common_name') or 'N/A'}`")
            st.markdown(f"- **Issuer CA**: `{cert.get('issuer_ca') or 'N/A'}`")
        with c2:
            st.markdown(f"- **Serial Number**: `{cert.get('serial_number') or 'N/A'}`")
            st.markdown(f"- **Valid From**: `{cert.get('valid_from') or 'N/A'}`")
            st.markdown(f"- **Valid To**: `{cert.get('valid_to') or 'N/A'}`")
            st.markdown(f"- **Clone Mismatch Detected**: `{cert.get('clone_mismatch_detected')}`")

    # TAB 5: JSON Viewer & Download
    with tab_json:
        st.markdown("#### Standardized IA3 JSON Payload")
        json_str = json.dumps(report, indent=2)
        st.download_button(
            label="⬇️ Download IA3 JSON Report",
            data=json_str,
            file_name=f"{file_info.get('filename')}_ia3_report.json",
            mime="application/json"
        )
        st.json(report)

else:
    st.info("Please select a demo sample from the sidebar or upload a file to begin.")
