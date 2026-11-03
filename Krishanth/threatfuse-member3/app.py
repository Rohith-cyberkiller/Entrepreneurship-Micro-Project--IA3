"""
ThreatFuse Dashboard: 3-Pillar Consensus & Final Trust Score Gateway
Member 3: Threat Intelligence & Decision Engine Lead
"""

import os
import sys
import json
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

# Configure page settings
st.set_page_config(
    page_title="ThreatFuse | 3-Pillar Trust Consensus Gateway",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from decision_engine.trust_scorer import compute_final_trust_score, evaluate_sample_consensus
from threat_intel.cache_manager import get_cached_threat_intel

# Rich Cyber CSS styling
CUSTOM_CSS = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;800&family=Plus+Jakarta+Sans:wght@400;600;700;800&display=swap');

    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    code, pre, .mono {
        font-family: 'JetBrains Mono', monospace !important;
    }

    .main .block-container {
        padding-top: 2rem;
        padding-bottom: 3rem;
        max-width: 1400px;
    }

    .metric-card {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 10px;
        padding: 16px;
        text-align: center;
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .metric-card:hover {
        border-color: #58a6ff;
        transform: translateY(-2px);
    }

    .verdict-banner-allow {
        background: rgba(46, 160, 67, 0.15);
        border: 2px solid #2ea043;
        color: #3fb950;
        border-radius: 10px;
        padding: 16px;
        text-align: center;
        font-weight: 800;
        font-size: 20px;
        letter-spacing: 0.5px;
    }

    .verdict-banner-warn {
        background: rgba(210, 153, 34, 0.15);
        border: 2px solid #d29922;
        color: #d29922;
        border-radius: 10px;
        padding: 16px;
        text-align: center;
        font-weight: 800;
        font-size: 20px;
        letter-spacing: 0.5px;
    }

    .verdict-banner-block {
        background: rgba(248, 81, 73, 0.15);
        border: 2px solid #f85149;
        color: #ff7b72;
        border-radius: 10px;
        padding: 16px;
        text-align: center;
        font-weight: 800;
        font-size: 20px;
        letter-spacing: 0.5px;
        animation: pulse 2s infinite;
    }

    @keyframes pulse {
        0% { box-shadow: 0 0 0 0 rgba(248, 81, 73, 0.4); }
        70% { box-shadow: 0 0 0 8px rgba(248, 81, 73, 0); }
        100% { box-shadow: 0 0 0 0 rgba(248, 81, 73, 0); }
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# Load sample inputs dataset
INPUTS_PATH = os.path.join(CURRENT_DIR, "data", "sample_m1_m2_inputs.json")
with open(INPUTS_PATH, "r", encoding="utf-8") as f:
    SAMPLE_INPUTS = json.load(f)

# Header
h_col1, h_col2 = st.columns([3, 1])
with h_col1:
    st.markdown("## 🛡️ ThreatFuse — 3-Pillar Consensus & Final Trust Gateway")
    st.markdown(
        "**IA3 Member 3 Deliverable**: VirusTotal v3 + MalwareBazaar API Integration, Zero-Day Weight Shifting & Multi-Module Decision Engine"
    )
with h_col2:
    st.markdown(
        """
        <div style="text-align: right; padding-top: 10px;">
            <span style="background: #8957e5; color: white; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 700;">GATEWAY ACTIVE</span>
            <div style="color: #8b949e; font-size: 11px; margin-top: 4px;">Dynamic Zero-Day Weighting</div>
        </div>
        """,
        unsafe_allow_html=True
    )

st.markdown("---")

# Sidebar Configuration
with st.sidebar:
    st.markdown("### ⚙️ Threat Intelligence Configuration")
    use_offline_cache = st.toggle("Offline Demo Cache Mode", value=True, help="Uses realistic cached responses for reliable offline demonstration without API quota limits.")

    vt_api_key = None
    mb_api_key = None

    if not use_offline_cache:
        vt_api_key = st.text_input("VirusTotal API v3 Key:", type="password", placeholder="Enter VT API Key...")
        mb_api_key = st.text_input("MalwareBazaar Auth Key (Optional):", type="password", placeholder="Enter MB Auth Key...")

    st.markdown("---")
    st.markdown("### 📥 Evaluation Input Selection")
    input_mode = st.radio(
        "Select Telemetry Source:",
        ["Standard IA3 Scenarios (1-4)", "Custom SHA-256 Hash", "Upload Member 1 & 2 JSON Reports"]
    )

    scenario_labels = {
        "Scenario 1: Official VLC Media Player Installer (Signed VideoLAN, Clean)": "scenario_1_vlc_clean",
        "Scenario 2: Counterfeit Google Chrome Trojan (RedLineStealer, Unsigned)": "scenario_2_fake_chrome_trojan",
        "Scenario 3: Brand-New Zero-Day Packed Installer (404 on Cloud Feeds)": "scenario_3_zero_day_packed",
        "Scenario 4: Minor Grayware / Adware Bundler (InstallCore, Low Rep)": "scenario_4_grayware_adware"
    }

    m1_payload = {}
    m2_payload = {}
    target_sha = None

    if input_mode == "Standard IA3 Scenarios (1-4)":
        chosen_label = st.selectbox("Choose Evaluation Scenario:", list(scenario_labels.keys()), index=1)
        sc_key = scenario_labels[chosen_label]
        sc_data = SAMPLE_INPUTS[sc_key]
        m1_payload = sc_data.get("member1_static", {})
        m2_payload = sc_data.get("member2_ml", {})
        target_sha = sc_data.get("sha256")
        st.info(f"Target: `{sc_data.get('filename')}`")

    elif input_mode == "Custom SHA-256 Hash":
        target_sha = st.text_input("Enter 64-character SHA-256:", value="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
        m1_payload = {"hashes": {"sha256": target_sha}}
        m2_payload = {"ml_prediction": {"malware_probability_score": 75.0}}

    else:
        up_m1 = st.file_uploader("Upload Member 1 Static JSON:", type=["json"], key="m1")
        up_m2 = st.file_uploader("Upload Member 2 ML Prediction JSON:", type=["json"], key="m2")
        if up_m1:
            m1_payload = json.load(up_m1)
            target_sha = m1_payload.get("hashes", {}).get("sha256") or m1_payload.get("sha256")
        if up_m2:
            m2_payload = json.load(up_m2)

    st.markdown("---")
    st.markdown("#### ⚖️ Consensus Weighting Rules")
    st.markdown("- **Cloud-Known Hash**: 50% Cloud TI + 30% ML + 20% Static")
    st.markdown("- **Zero-Day (404)**: 55% ML + 45% Static + 0% Cloud TI")
    st.markdown("- **Kill-Switch Threshold**: Risk floored at 90.0+ on confirmed threats")

# Run Consensus Engine
if target_sha:
    if use_offline_cache:
        cached_ti = get_cached_threat_intel(target_sha)
        ti_bundle = {
            "sha256": target_sha,
            "virustotal": cached_ti.get("virustotal", {}),
            "malwarebazaar": cached_ti.get("malwarebazaar", {})
        }
        consensus_report = compute_final_trust_score(m1_payload, m2_payload, ti_bundle)
    else:
        consensus_report = evaluate_sample_consensus(
            target_sha,
            member1_json=m1_payload,
            member2_json=m2_payload,
            api_key_vt=vt_api_key,
            api_key_mb=mb_api_key
        )

    breakdown = consensus_report["component_risk_breakdown"]
    decision = consensus_report["final_decision"]
    ti = consensus_report["threat_intelligence"]
    vt = ti.get("virustotal", {})
    mb = ti.get("malwarebazaar", {})

    trust_score = decision["final_trust_score"]
    risk_score = decision["final_risk_score"]
    action = decision["recommended_action"]
    verdict = decision["verdict"]
    overrides = decision.get("critical_overrides_triggered", [])

    # Action Banner
    if action == "ALLOW":
        st.markdown(f'<div class="verdict-banner-allow">✅ {verdict} &nbsp;|&nbsp; RECOMMENDED ACTION: ALLOW INSTALLATION</div>', unsafe_allow_html=True)
    elif action == "WARN_USER":
        st.markdown(f'<div class="verdict-banner-warn">⚠️ {verdict} &nbsp;|&nbsp; RECOMMENDED ACTION: WARN USER</div>', unsafe_allow_html=True)
    else:
        st.markdown(f'<div class="verdict-banner-block">🚨 {verdict} &nbsp;|&nbsp; RECOMMENDED ACTION: BLOCK & QUARANTINE</div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Top KPI Metrics Row
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(
            f"""
            <div class="metric-card">
                <div style="color: #8b949e; font-size: 12px; font-weight: 600; text-transform: uppercase;">FINAL TRUST SCORE</div>
                <div style="font-size: 28px; font-weight: 800; color: {'#3fb950' if trust_score >= 75 else '#d29922' if trust_score >= 40 else '#ff7b72'}; margin-top: 2px;">
                    {trust_score:.2f} <span style="font-size: 14px; color: #8b949e; font-weight: 400;">/ 100</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with c2:
        st.markdown(
            f"""
            <div class="metric-card">
                <div style="color: #8b949e; font-size: 12px; font-weight: 600; text-transform: uppercase;">COMBINED RISK INDEX</div>
                <div style="font-size: 28px; font-weight: 800; color: {'#ff7b72' if risk_score >= 60 else '#d29922' if risk_score >= 25 else '#3fb950'}; margin-top: 2px;">
                    {risk_score:.2f}%
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with c3:
        vt_mal = vt.get("malicious_count", 0)
        vt_tot = vt.get("total_engines", 0)
        vt_color = "#ff7b72" if vt_mal >= 5 else "#d29922" if vt_mal > 0 else "#3fb950"
        st.markdown(
            f"""
            <div class="metric-card">
                <div style="color: #8b949e; font-size: 12px; font-weight: 600; text-transform: uppercase;">VIRUSTOTAL DETECTIONS</div>
                <div style="font-size: 24px; font-weight: 800; color: {vt_color}; margin-top: 2px;">
                    {vt_mal} <span style="font-size: 14px; color: #8b949e; font-weight: 400;">/ {vt_tot} engines</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with c4:
        mb_match = mb.get("found", False)
        mb_color = "#ff7b72" if mb_match else "#3fb950"
        mb_label = mb.get("signature_family") if mb_match else "No Malware Match"
        st.markdown(
            f"""
            <div class="metric-card">
                <div style="color: #8b949e; font-size: 12px; font-weight: 600; text-transform: uppercase;">MALWAREBAZAAR STATUS</div>
                <div style="font-size: 18px; font-weight: 700; color: {mb_color}; margin-top: 6px;">
                    {'⚠️ ' + str(mb_label) if mb_match else '🛡️ ' + str(mb_label)}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("<br>", unsafe_allow_html=True)

    # Main Visuals: Final Trust Gauge (Left) & 3-Pillar Component Comparison (Right)
    g_col, comp_col = st.columns([1.2, 1.8])

    with g_col:
        # Trust Score Gauge
        gauge_color = "#3fb950" if trust_score >= 75 else "#d29922" if trust_score >= 40 else "#ff7b72"
        fig_trust = go.Figure(go.Indicator(
            mode="gauge+number",
            value=trust_score,
            title={'text': "Final Pre-Execution Trust Score", 'font': {'size': 18, 'color': '#f0f6fc'}},
            number={'valueformat': ".2f", 'font': {'color': gauge_color, 'family': 'JetBrains Mono', 'size': 38}},
            domain={'x': [0, 1], 'y': [0, 1]},
            gauge={
                'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "#8b949e", 'nticks': 6},
                'bar': {'color': gauge_color},
                'bgcolor': "#161b22",
                'borderwidth': 2,
                'bordercolor': "#30363d",
                'steps': [
                    {'range': [0, 40], 'color': "rgba(248, 81, 73, 0.35)"},
                    {'range': [40, 75], 'color': "rgba(210, 153, 34, 0.25)"},
                    {'range': [75, 100], 'color': "rgba(63, 185, 80, 0.25)"}
                ],
                'threshold': {
                    'line': {'color': "#2ea043", 'width': 3},
                    'thickness': 0.8,
                    'value': 75.0
                }
            }
        ))
        fig_trust.update_layout(
            height=280,
            margin=dict(l=20, r=20, t=50, b=20),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)"
        )
        st.plotly_chart(fig_trust, use_container_width=True)

        st.caption(f"Strategy: **{breakdown['weighting_strategy_used']}**")

    with comp_col:
        # 3-Pillar Bar Comparison Chart
        pillars = ["Member 1: Static Binary", "Member 2: ML Probability", "Member 3: Cloud Threat Intel"]
        s_m1 = breakdown["member1_static_risk_score"]
        s_m2 = breakdown["member2_ml_probability_score"]
        s_m3 = breakdown["member3_threat_intel_risk_score"]
        s_m3_val = s_m3 if isinstance(s_m3, (int, float)) else 0.0

        risk_values = [s_m1, s_m2, s_m3_val]
        weights = [
            breakdown["active_weights"]["member1_static"] * 100,
            breakdown["active_weights"]["member2_ml"] * 100,
            breakdown["active_weights"]["member3_ti"] * 100
        ]

        fig_comp = go.Figure()
        fig_comp.add_trace(go.Bar(
            name="Component Risk Score (%)",
            x=pillars,
            y=risk_values,
            marker_color=["#ff7b72" if v >= 70 else "#d29922" if v >= 30 else "#3fb950" for v in risk_values],
            text=[f"{v:.1f}%" for v in risk_values],
            textposition="auto"
        ))
        fig_comp.add_trace(go.Bar(
            name="Assigned Weight in Consensus (%)",
            x=pillars,
            y=weights,
            marker_color="#8957e5",
            text=[f"{w:.0f}% Weight" for w in weights],
            textposition="auto"
        ))
        fig_comp.update_layout(
            title="3-Pillar Component Risk vs. Active Dynamic Weights",
            barmode="group",
            yaxis=dict(title="Score / Weight Percentage", range=[0, 115]),
            height=300,
            margin=dict(l=20, r=20, t=40, b=20),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#f0f6fc"),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
        )
        st.plotly_chart(fig_comp, use_container_width=True)

    # Critical Kill-Switch Overrides Callout
    if overrides:
        st.error(f"🚨 **CRITICAL KILL-SWITCH OVERRIDES ENFORCED** ({len(overrides)} Hard Rules Triggered — Trust Score capped at <= 10.0):")
        for o in overrides:
            st.markdown(f"- **{o}**")

    st.markdown("---")

    # Detailed Tabs
    t_intel, t_breakdown, t_json = st.tabs([
        "🌐 Cloud Threat Intelligence Details",
        "⚖️ Component Weights & Math Explanations",
        "📄 Standardized Final Merged JSON Report"
    ])

    with t_intel:
        ti_col1, ti_col2 = st.columns(2)
        with ti_col1:
            st.markdown("#### VirusTotal v3 Intelligence")
            st.markdown(f"- **Detection Ratio**: `{vt.get('detection_ratio_pct', 0.0)}%` ({vt.get('malicious_count', 0)}/{vt.get('total_engines', 0)} engines)")
            st.markdown(f"- **Threat Label**: `{vt.get('threat_label') or 'Clean / Unclassified'}`")
            st.markdown(f"- **Community Reputation**: `{vt.get('reputation', 0)}`")
            st.markdown(f"- **Times Submitted**: `{vt.get('times_submitted', 0):,}`")
            st.markdown(f"- **Telemetry Source**: `{vt.get('source', 'Unknown')}`")

        with ti_col2:
            st.markdown("#### MalwareBazaar (abuse.ch) Intelligence")
            st.markdown(f"- **Family Signature**: `{mb.get('signature_family') or 'Not listed in malware corpus'}`")
            st.markdown(f"- **File Type**: `{mb.get('file_type') or 'N/A'}`")
            tags = mb.get("tags", [])
            st.markdown(f"- **Threat Tags**: {', '.join([f'`{t}`' for t in tags]) if tags else 'None'}")
            yara = mb.get("yara_rules", [])
            st.markdown(f"- **Triggered YARA Rules**: {', '.join([f'`{y}`' for t in yara]) if yara else 'None'}")
            st.markdown(f"- **Telemetry Source**: `{mb.get('source', 'Unknown')}`")

    with t_breakdown:
        st.markdown("#### Consensus Mathematics")
        st.markdown(
            f"""
            - **Member 1 (Static Analysis Risk)**: `{breakdown['member1_static_risk_score']}%`
            - **Member 2 (Machine Learning Probability)**: `{breakdown['member2_ml_probability_score']}%`
            - **Member 3 (Cloud Threat Intel Risk)**: `{breakdown['member3_threat_intel_risk_score']}`
            - **Active Weighting Formula**:
              `Final_Risk = ({breakdown['active_weights']['member1_static']} × S_M1) + ({breakdown['active_weights']['member2_ml']} × S_M2) + ({breakdown['active_weights']['member3_ti']} × S_M3)`
            - **Final Trust Score Calculation**:
              `Final_Trust_Score = 100.0 - Final_Risk = 100.0 - {risk_score:.2f} = {trust_score:.2f}`
            """
        )

    with t_json:
        st.markdown("#### Final Standardized Consensus JSON Payload")
        merged_json_str = json.dumps(consensus_report, indent=2)
        st.download_button(
            label="⬇️ Download Final Merged Trust Score JSON",
            data=merged_json_str,
            file_name=f"{target_sha[:12]}_trust_consensus.json",
            mime="application/json"
        )
        st.json(consensus_report)

else:
    st.info("Select a scenario or upload JSON telemetry to evaluate consensus trust score.")
