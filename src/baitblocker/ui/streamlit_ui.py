import base64
import binascii

import plotly.graph_objects as go
import streamlit as st
import requests

# Configure the page layout
st.set_page_config(
    page_title="BaitBlocker Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# API Endpoint definitions
FASTAPI_ANALYZE = "http://localhost:8000/analyze"

st.title("🛡️ Bait Blocker Threat Analysis Engine")
st.subheader("Phishing Detection Engine ver 1.0.0")
st.caption("Built by Yehoshua Gruenspecht")

st.markdown("---")

st.sidebar.image("BaitBlockerLogoV1.png")
st.sidebar.header("⚙️ Engine Configurations")
activate_sandbox = st.sidebar.checkbox(
    "Enable Deep Visual Sandbox",
    value=False,
    help="Spins up an isolated headless browser instance to capture a secure screenshot. Increases execution runtime."
)
st.sidebar.header("🐟 About")
st.sidebar.markdown("Bait Blocker is an anti-phishing tool that uses local and external engines to analyze URLs, AI LLMs to analyze email text and playwright sandbox to screenshot suspicious websites."
                    " For quick running we recommend only testing the URL as Bait Blocker has a cache of already seen URLs."
                    ""
                    "  :blue-background[Customer Support - yehoshua809.tech@gmail.com]")

# Layout: Split into two columns for input
col1, col2 = st.columns(2)

with col1:
    st.subheader("🔗 URL Threat Analysis")
    url_input = st.text_input("Enter URL to scan:", placeholder="https://signin-netflix.xyz")

with col2:
    st.subheader("📧 Email Content Analysis")
    email_input = st.text_area("Paste suspicious email text:", placeholder="Urgent: update your invoice billing info.")

# Trigger Button
st.markdown("###")
if st.button("🚀 Analyze Threats", use_container_width=True):

    if not url_input and not email_input:
        st.error("❌ Please provide either a URL or email text to analyze.")
    else:
        # Define and normalize inputs to safely package the outgoing JSON object
        clean_url = url_input.strip() if url_input else None
        clean_email = email_input.strip() if email_input else None

        with st.spinner("Running core lexical and threat intelligence engines..."):  # type: ignore
            try:
                cache_status = "UNKNOWN"

                # Prepare the standardized POST payload
                payload = {
                    "url": clean_url,
                    "email_text": clean_email,
                    "run_sandbox": activate_sandbox
                }

                # Hit your comprehensive endpoint using POST
                response = requests.post(FASTAPI_ANALYZE, json=payload)

                # --- RENDER DASHBOARD RESPONSES ---
                if response.status_code == 200:
                    data = response.json()

                    cache_status = response.headers.get("X-Cache", response.headers.get("x-cache", "UNKNOWN")).upper()

                    local_rep = data.get("local_report", {}) or {}
                    ext_rep = data.get("external_report", {}) or {}
                    sandbox = data.get("sandbox", {}) or {}

                    st.success("Analysis Complete!")

                    # Display explicit cache/bypass state from backend headers
                    if cache_status == "HIT":
                        st.info("⚡ **Cache Hit!** Response served instantly from FastAPI RAM memory backend.")
                    elif cache_status == "MISS":
                        st.warning("🐢 **Cache Miss / Deep Scan:** Core execution pipeline invoked.")
                    elif cache_status == "BYPASS":
                        st.info("ℹ️ **Cache Bypass:** No URL was provided, so URL cache was not used.")
                    else:
                        st.info("ℹ️ Cache status unavailable for this request.")

                    st.markdown("---")

                    # DISPLAY RESULTS IN TABS
                    tab1, tab2, tab3, tab4, tab5 = st.tabs(
                        ["📊 Executive Summary","🤖 Machine Learning Prediction", "🧠 Local Logic Analytics", "🌐 External Threat Intelligence", "🖼️ Live Sandbox View"])

                    with tab1:
                        st.subheader("Quick Metrics Overview")
                        m_col1, m_col2, m_col3, m_col4, m_col5, m_col6 = st.columns(6)

                        lex_data = local_rep.get("url_lexical_analysis") or {}
                        ml_data = local_rep.get("ml_report")
                        lex_risk = float(lex_data.get("risk_score", 0.0))
                        ml_risk = float(ml_data.get("phishing_probability", 0.0)) if ml_data else 0.0
                        risk_score = (0.3 * lex_risk) + (0.7 * ml_risk)
                        verdict = lex_data.get("verdict", "N/A")
                        prediction = ml_data.get("is_phishing", "N/A") if ml_data else False

                        vt_flagged = ext_rep.get("engines_flagged_on_vt", 0)
                        google_flagged = ext_rep.get("google_safe_browsing", "N/A")

                        email_verdict = local_rep.get("email_text_analysis") or {}
                        email_prob = float(email_verdict.get("phishing_probability", 0.0))
                        email_risk = email_verdict.get("risk_level", "N/A")

                        with m_col1:
                            st.metric(label="URL Risk",
                                      value=f"{risk_score:.2f}")
                            st.metric(label="Email Risk",
                                      value=f"{email_prob:.2f}")
                            st.metric(label="Total Phishing Score",
                                      value=f"{risk_score + email_prob:.2f}")
                        with m_col2:
                            st.metric(label="ML Prediction", value=prediction, delta=f"Probability: {ml_risk}")
                        with m_col3:
                            st.metric(label="Lexical Verdict", value=verdict, delta=f"Risk: {lex_risk}")
                        with m_col4:
                            st.metric(label="VirusTotal Flags", value=f"{vt_flagged} Engines",
                                      delta="Status: " + str(ext_rep.get("risk_level_from_virus_total", "N/A")))
                        with m_col5:
                            st.metric(label="Google Safe Browsing", value=str(google_flagged))
                        with m_col6:
                            st.metric(label="Email Verdict", value=email_risk,
                                      delta=f"Score: {email_prob}")

                    with tab2:
                        st.subheader("Machine Learning Report")

                        if not ml_data:
                            st.info("No ML prediction available for this input.")
                        else:
                            phishing_prob = float(ml_data.get("phishing_probability", 0.0))
                            safe_prob = float(ml_data.get("safe_probability", 1.0 - phishing_prob))
                            is_phishing_ml = ml_data.get("is_phishing", False)
                            threshold = 0.6

                            verdict_color = "#e74c3c" if is_phishing_ml else "#2ecc71"
                            verdict_label = "⚠️ PHISHING" if is_phishing_ml else "✅ SAFE"

                            st.markdown(
                                f"<h3 style='color:{verdict_color}; text-align:center'>{verdict_label}</h3>",
                                unsafe_allow_html=True
                            )

                            # ── GAUGE CHART ─────────────────────────────────────────────
                            gauge_fig = go.Figure(go.Indicator(
                                mode="gauge+number+delta",
                                value=round(phishing_prob * 100, 1),
                                delta={
                                    "reference": threshold * 100,
                                    "increasing": {"color": "#e74c3c"},
                                    "decreasing": {"color": "#2ecc71"},
                                    "suffix": "% vs threshold",
                                },
                                number={"suffix": "%", "font": {"size": 36}},
                                title={"text": "Phishing Probability", "font": {"size": 18}},
                                gauge={
                                    "axis": {"range": [0, 100], "ticksuffix": "%"},
                                    "bar": {"color": verdict_color, "thickness": 0.3},
                                    "steps": [
                                        {"range": [0, 40], "color": "#d5f5e3"},
                                        {"range": [40, 60], "color": "#fef9e7"},
                                        {"range": [60, 100], "color": "#fadbd8"},
                                    ],
                                    "threshold": {
                                        "line": {"color": "#2c3e50", "width": 3},
                                        "thickness": 0.85,
                                        "value": threshold * 100,
                                    },
                                },
                            ))
                            gauge_fig.update_layout(
                                height=300,
                                margin=dict(t=60, b=20, l=40, r=40),
                                paper_bgcolor="rgba(0,0,0,0)",
                            )
                            st.plotly_chart(gauge_fig, use_container_width=True)

                            st.caption(
                                f"Decision threshold: **{int(threshold * 100)}%** — "
                                f"phishing probability: **{phishing_prob:.1%}** | "
                                f"safe probability: **{safe_prob:.1%}**"
                            )

                            # ── FEATURE CONTRIBUTION BAR CHART ──────────────────────────
                            contributions = ml_data.get("feature_contributions") or {}
                            if contributions:
                                st.markdown("---")
                                st.markdown("#### Feature Contributions to This Prediction")
                                st.caption(
                                    "Bars to the **right** (red) push toward phishing. "
                                    "Bars to the **left** (green) push toward safe. "
                                    "Only non-zero contributions are shown."
                                )

                                # Filter to only non-zero contributions and sort by absolute magnitude
                                active = {k: v for k, v in contributions.items() if abs(v) > 0.001}
                                if active:
                                    sorted_items = sorted(active.items(), key=lambda x: x[1])
                                    feat_names = [item[0] for item in sorted_items]
                                    feat_vals = [item[1] for item in sorted_items]
                                    bar_colors = [
                                        "#e74c3c" if v > 0 else "#2ecc71"
                                        for v in feat_vals
                                    ]

                                    contrib_fig = go.Figure(go.Bar(
                                        x=feat_vals,
                                        y=feat_names,
                                        orientation="h",
                                        marker_color=bar_colors,
                                        text=[f"{v:+.3f}" for v in feat_vals],
                                        textposition="outside",
                                        hovertemplate="%{y}: %{x:+.4f}<extra></extra>",
                                    ))
                                    contrib_fig.update_layout(
                                        xaxis_title="Contribution (scaled feature × coefficient)",
                                        yaxis_title="",
                                        height=max(300, 28 * len(feat_names)),
                                        margin=dict(l=160, r=60, t=20, b=40),
                                        paper_bgcolor="rgba(0,0,0,0)",
                                        plot_bgcolor="rgba(0,0,0,0)",
                                        xaxis=dict(zeroline=True, zerolinecolor="#888", gridcolor="#eee"),
                                        yaxis=dict(gridcolor="#eee"),
                                    )
                                    st.plotly_chart(contrib_fig, use_container_width=True)
                                else:
                                    st.info("All feature contributions are near zero for this URL (it looks structurally unremarkable).")
                            else:
                                st.write(ml_data)


                    with tab3:
                        st.subheader("Internal Rules Engine Output")
                        if local_rep.get("url_lexical_analysis"):
                            st.markdown("**URL Flagged Reasons:**")
                            for reason in local_rep["url_lexical_analysis"].get("reasons", []):
                                st.warning(f"⚠️ {reason}")

                        if clean_email and local_rep.get("email_text_analysis"):
                            st.markdown("**Email Text Analysis Raw Findings:**")
                            st.write(local_rep["email_text_analysis"])
                        else:
                            st.info("No email text was processed during this run.")

                    with tab4:
                        st.subheader("Third-Party Intelligence Reputations")
                        st.json(ext_rep)

                    with tab5:
                        st.subheader("Isolated Visual Replication Profile")

                        sandbox_status = sandbox.get("sandbox_status", "N/A")
                        final_dest = sandbox.get("final_destination", "N/A")
                        screenshot_str = sandbox.get("screenshot_data")

                        st.markdown(f"**Final Destination Hook:** `{final_dest}`")
                        st.markdown(f"**Sandbox State:** `{sandbox_status}`")

                        if screenshot_str:
                            # Decode the string bytes directly into a visual browser block on the fly
                            try:
                                img_bytes = base64.b64decode(screenshot_str)
                                st.image(
                                    img_bytes,
                                    caption="Visual payload signature captured within safe, headless cloud instance.",
                                )
                            except (binascii.Error, ValueError, TypeError):
                                st.info("No visual artifact captured for this entry. Ensure the target URL is active.")
                        else:
                            st.info("No visual artifact captured for this entry. Ensure the target URL is active.")

                else:
                    st.error(f"Backend API returned an error status ({response.status_code}): {response.text}")

            except requests.exceptions.ConnectionError:
                st.error(
                    "🔴 Could not connect to the FastAPI backend. Make sure your Uvicorn server is running on localhost:8000!")

