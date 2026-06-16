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

log_col, title_col = st.columns([1, 4])

with log_col:
    st.image("BaitBlockerLogoV1.png")

with title_col:
    st.title("🛡️ BaitBlocker Threat Analysis Engine")
    st.subheader("Phishing Detection Engine ver 1.0.0")
    st.caption("Built by Yehoshua Gruenspecht")

st.markdown("---")

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
                is_cache_hit = False

                # Prepare the standardized POST payload
                payload = {
                    "url": clean_url,
                    "email_text": clean_email
                }

                # Hit your comprehensive endpoint using POST
                response = requests.post(FASTAPI_ANALYZE, json=payload)

                # --- RENDER DASHBOARD RESPONSES ---
                if response.status_code == 200:
                    data = response.json()

                    # Track cache hits using case-insensitive lowercase matching
                    if "x-cache" not in response.headers:
                        is_cache_hit = True

                    local_rep = data.get("local_report", {}) or {}
                    ext_rep = data.get("external_report", {}) or {}

                    st.success("Analysis Complete!")

                    # Display explicit Cache Badge based on HTTP Headers
                    if is_cache_hit:
                        st.info("⚡ **Cache Hit!** Response served instantly from FastAPI RAM memory backend.")
                    else:
                        st.warning("🐢 **Cache Miss / Deep Scan:** Core execution pipeline invoked.")

                    st.markdown("---")

                    # DISPLAY RESULTS IN TABS
                    tab1, tab2, tab3 = st.tabs(
                        ["📊 Executive Summary", "🧠 Local Logic Analytics", "🌐 External Threat Intelligence"])

                    with tab1:
                        st.subheader("Quick Metrics Overview")
                        m_col1, m_col2, m_col3, m_col4, m_col5 = st.columns(5)

                        lex_data = local_rep.get("url_lexical_analysis") or {}
                        risk_score = float(lex_data.get("risk_score", 0.0))
                        verdict = lex_data.get("verdict", "N/A")

                        vt_flagged = ext_rep.get("engines_flagged_on_vt", 0)
                        google_flagged = ext_rep.get("google_safe_browsing", "N/A")

                        email_verdict = local_rep.get("email_text_analysis") or {}
                        email_prob = float(email_verdict.get("phishing_probability", 0.0))
                        email_risk = email_verdict.get("risk_level", "N/A")

                        with m_col1:
                            st.metric(label="Total Phishing Score",
                                      value=f"{risk_score + email_prob:.2f}")
                        with m_col2:
                            st.metric(label="Lexical Verdict", value=verdict, delta=f"Risk: {risk_score}")
                        with m_col3:
                            st.metric(label="VirusTotal Flags", value=f"{vt_flagged} Engines",
                                      delta="Status: " + str(ext_rep.get("risk_level_from_virus_total", "N/A")))
                        with m_col4:
                            st.metric(label="Google Safe Browsing", value=str(google_flagged))
                        with m_col5:
                            st.metric(label="Email Verdict", value=email_risk,
                                      delta=f"Score: {email_prob}")

                    with tab2:
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

                    with tab3:
                        st.subheader("Third-Party Intelligence Reputations")
                        st.json(ext_rep)

                else:
                    st.error(f"Backend API returned an error status ({response.status_code}): {response.text}")

            except requests.exceptions.ConnectionError:
                st.error(
                    "🔴 Could not connect to the FastAPI backend. Make sure your Uvicorn server is running on localhost:8000!")