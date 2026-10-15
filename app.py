from phishguard.batch_scanner import scan_urls
import streamlit as st
import pandas as pd

from phishguard.url_analyzer import analyze_url
from phishguard.raw_url_predictor import predict_url


st.set_page_config(
    page_title="PhishGuard AI",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ PhishGuard AI")
st.subheader("Intelligent Phishing URL Risk Analyzer")

st.write(
    "Analyze URL structure, identify suspicious indicators, "
    "and understand why a URL may deserve closer inspection."
)

st.warning(
    "This tool analyzes URL text only. It does not visit the URL. "
    "Its heuristic score is not proof that a URL is safe or malicious."
)

url = st.text_input(
    "Enter a URL to analyze",
    placeholder="https://example.com",
)

analyze_button = st.button(
    "Analyze URL",
    type="primary",
    use_container_width=True,
)

if analyze_button:
    if not url.strip():
        st.error("Please enter a URL first.")
    else:
        try:
            result = analyze_url(url)
            
            ml_result = predict_url(url)


            st.divider()
            st.subheader("Analysis Results")

            col1, col2, col3 = st.columns(3)

            with col1:
                st.metric("Risk Score", f'{result["risk_score"]}/100')

            with col2:
                st.metric("Risk Level", result["risk_level"])

            with col3:
                st.metric("Scheme", result["scheme"].upper())

            score = result["risk_score"]
            st.progress(score / 100)

            if result["risk_level"] == "High":
                st.error("High heuristic risk — investigate carefully.")
            elif result["risk_level"] == "Medium":
                st.warning("Medium heuristic risk — review the indicators.")
            else:
                st.success("Low heuristic risk — this does not guarantee safety.")

            st.markdown("### URL Details")
            st.write("**Submitted URL:**", result["url"])
            st.write("**Hostname:**", result["hostname"])

            st.markdown("### Why was this URL flagged?")

            for indicator in result["indicators"]:
                st.markdown(f"- {indicator}")

            st.caption(result["note"])
            
            st.divider()
            st.subheader("Machine Learning Prediction")

            ml_col1, ml_col2 = st.columns(2)

            with ml_col1:
                st.metric(
                    "ML Prediction",
                    ml_result["prediction"].title(),
                )

            with ml_col2:
                st.metric(
                    "Estimated Phishing Probability",
                    f'{ml_result["phishing_probability"]:.1%}',
                )

            st.progress(ml_result["phishing_probability"])
            st.caption(ml_result["note"])


            report = pd.DataFrame(
                [
                    {"Field": "URL", "Value": result["url"]},
                    {"Field": "Hostname", "Value": result["hostname"]},
                    {"Field": "Risk Score", "Value": score},
                    {"Field": "Risk Level", "Value": result["risk_level"]},
                    {
                        "Field": "Indicators",
                        "Value": "; ".join(result["indicators"]),
                    },
                ]
            )

            st.download_button(
                "Download Analysis Report (CSV)",
                data=report.to_csv(index=False).encode("utf-8"),
                file_name="phishguard_analysis.csv",
                mime="text/csv",
            )

        except ValueError as exc:
            st.error(str(exc))

st.divider()
st.caption("PhishGuard AI | URL analysis without visiting submitted websites")

st.divider()
st.header("📁 Batch URL Scanner")
st.write("Upload a CSV file containing a column named `url`.")

uploaded_file = st.file_uploader(
    "Upload URL CSV",
    type=["csv"],
    key="batch_url_csv",
)

if uploaded_file is not None:
    try:
        batch_input = pd.read_csv(uploaded_file)

        if "url" not in batch_input.columns:
            st.error("Your CSV must contain a column named 'url'.")
        elif len(batch_input) > 5000:
            st.error("Please upload a CSV containing at most 5,000 URLs.")
        else:
            if st.button("Scan All URLs", type="primary"):
                batch_results = scan_urls(
                    batch_input["url"].fillna("").astype(str).tolist()
                )
                st.session_state["batch_results"] = batch_results

            if "batch_results" in st.session_state:
                results = st.session_state["batch_results"]

                st.subheader("Batch Scan Results")

                
                col1, col2, col3, col4 = st.columns(4)

                col1.metric("URLs Processed", len(results))
                col2.metric(
                    "High Heuristic Risk",
                    int((results["risk_level"] == "High").sum()),
                )
                col3.metric(
                    "ML Phishing Predictions",
                    int((results["ml_prediction"] == "phishing").sum()),
                )
                col4.metric(
                    "Invalid URLs",
                    int((results["risk_level"] == "Invalid").sum()),
                )


                st.dataframe(results, use_container_width=True)

                st.download_button(
                    "Download Batch Report",
                    data=results.to_csv(index=False).encode("utf-8"),
                    file_name="phishguard_batch_report.csv",
                    mime="text/csv",
                )

    except (ValueError, pd.errors.ParserError, UnicodeDecodeError):
        st.error("Unable to read this CSV. Please check the file format.")
