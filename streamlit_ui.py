import streamlit as st
import requests

# Configure the page layout
st.set_page_config(
    page_title="BaitBlocker Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# API Endpoint definition (Assuming FastAPI runs on port 8000)
FASTAPI_URL = "http://localhost:8000/analyze"

# Title and Description
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

    # 1. Validate that at least one input exists
    if not url_input and not email_input:
        st.error("❌ Please provide either a URL or email text to analyze.")
    else:
        # Prepare the payload according to your FastAPI AnalysisRequest schema
        payload = {
            "url": url_input if url_input else None,
            "email_text": email_input if email_input else None
        }

        with st.spinner("Running core lexical and threat intelligence engines..."): # type: ignore
            try:
                # 2. Hit the FastAPI endpoint
                response = requests.post(FASTAPI_URL, json=payload)

                if response.status_code == 200:
                    data = response.json()
                    local_rep = data.get("local_report", {})
                    ext_rep = data.get("external_report", {})

                    st.success("Analysis Complete!")
                    st.markdown("---")

                    # 3. DISPLAY RESULTS IN TABS
                    tab1, tab2, tab3 = st.tabs(
                        ["📊 Executive Summary", "🧠 Local Logic Analytics", "🌐 External Threat Intelligence"])

                    with tab1:
                        st.subheader("Quick Metrics Overview")
                        m_col1, m_col2, m_col3, m_col4 = st.columns(4)

                        # Extract quick variables safely
                        lex_data = local_rep.get("url_lexical_analysis") or {}
                        risk_score = lex_data.get("risk_score", 0.0)
                        verdict = lex_data.get("verdict", "N/A")
                        vt_flagged = ext_rep.get("engines_flagged_on_vt", 0)
                        google_flagged = ext_rep.get("google_safe_browsing", "N/A")
                        final_verdict = ""
                        if verdict == "Safe" and vt_flagged == 0 and google_flagged == "Clean":
                            final_verdict = "Clean"
                        elif verdict == "N/A" or google_flagged == "N/A":
                            final_verdict = "Unclear"
                        else:
                            final_verdict = "Suspicious"

                        with m_col1:
                            st.metric(label="Final Verdict", value=final_verdict)
                        with m_col2:
                            st.metric(label="Lexical Verdict", value=verdict, delta="Risk Score: " + str(risk_score))
                        with m_col3:
                            st.metric(label="VirusTotal Flags", value=f"{vt_flagged} Engines",
                                      delta="Status: " + str(ext_rep.get("risk_level_from_virus_total", "N/A")))
                        with m_col4:
                            st.metric(label="Google Safe Browsing",
                                      value=ext_rep.get("google_safe_browsing") or "Not Evaluated")

                    with tab2:
                        st.subheader("Internal Rules Engine Output")

                        if local_rep.get("url_lexical_analysis"):
                            st.markdown("**URL Flagged Reasons:**")
                            for reason in local_rep["url_lexical_analysis"].get("reasons", []):
                                st.warning(f"⚠️ {reason}")

                        if local_rep.get("email_text_keyword_analysis"):
                            st.markdown("**Email Text Analysis Raw Findings:**")
                            st.write(local_rep["email_text_keyword_analysis"])
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