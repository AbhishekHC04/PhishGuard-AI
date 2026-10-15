
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import streamlit as st

from phishguard.batch_scanner import scan_urls
from phishguard.raw_url_predictor import predict_url
from phishguard.url_analyzer import analyze_url


st.set_page_config(
    page_title="PhishGuard AI | Threat Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------- THEME ----------
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }

    .stApp {
        background:
            radial-gradient(ellipse at top left, #102b35 0%, transparent 38%),
            linear-gradient(135deg, #07111f 0%, #0b1424 55%, #0b1924 100%);
        color: #e6edf7;
    }

    [data-testid="stSidebar"] {
        background: #0a1422;
        border-right: 1px solid #223247;
    }

    .hero {
        padding: 26px 28px;
        border: 1px solid #263b4d;
        border-radius: 18px;
        background: linear-gradient(120deg, #112738, #10201f);
        margin-bottom: 24px;
    }

    .eyebrow {
        color: #45e0b1;
        font-size: 12px;
        font-weight: 800;
        letter-spacing: 2px;
    }

    .hero h1 {
        color: #f4f8ff;
        font-size: clamp(30px, 4vw, 46px);
        font-weight: 800;
        margin: 8px 0;
    }

    .hero p {
        color: #a5b7c9;
        margin-bottom: 0;
    }

    .panel {
        padding: 20px;
        border-radius: 16px;
        border: 1px solid #26374b;
        background: rgba(15, 28, 44, 0.86);
        margin-bottom: 12px;
    }

    .muted {
        color: #93a7bb;
        font-size: 13px;
    }

    div[data-testid="stMetric"] {
        background: rgba(16, 31, 47, 0.9);
        border: 1px solid #26374b;
        padding: 16px;
        border-radius: 14px;
    }

    div[data-testid="stMetricLabel"] {
        color: #9bb0c5;
    }

    div[data-testid="stMetricValue"] {
        color: #f4f8ff;
    }

    .stButton > button[kind="primary"] {
        background: linear-gradient(90deg, #0d9474, #17b88d);
        border: 0;
        color: white;
        font-weight: 700;
        border-radius: 10px;
        min-height: 44px;
    }

    .stButton > button {
        border-radius: 10px;
    }

    h1, h2, h3 {
        color: #f4f8ff;
    }

/* Improve text contrast */
.stApp p,
.stApp label,
.stApp span {
    color: #e6edf7;
}

[data-testid="stSidebar"] p,
[data-testid="stSidebar"] label,
[data-testid="stSidebar"] span {
    color: #c4d2e2 !important;
}

div[data-testid="stMetricLabel"] {
    color: #b9c9d9 !important;
}

div[data-testid="stMetricValue"] {
    color: #f4f8ff !important;
}    
/* Improve download button contrast */
.stDownloadButton > button {
    background-color: #1f2937 !important;
    color: #f4f8ff !important;
    border: 1px solid #35cba2 !important;
    border-radius: 10px !important;
    font-weight: 600 !important;
}

.stDownloadButton > button:hover {
    background-color: #26384a !important;
    color: #ffffff !important;
    border-color: #35cba2 !important;
}

</style>
    """,
    unsafe_allow_html=True,
)

# ---------- STATE ----------
if "scan_history" not in st.session_state:
    st.session_state.scan_history = []

if "batch_results" not in st.session_state:
    st.session_state.batch_results = None



def make_gauge(probability):
    value = max(0.0, min(100.0, probability * 100))
    color = (
        "#ef6464" if value >= 70
        else "#f3b94f" if value >= 35
        else "#37d6a0"
    )

    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=value,
            number={
                "suffix": "%",
                "valueformat": ".1f",
                "font": {"color": "#f4f8ff", "size": 38},
            },
            title={
                "text": "ESTIMATED PHISHING PROBABILITY",
                "font": {"color": "#b9c9d9", "size": 13},
            },
            gauge={
                "axis": {
                    "range": [0, 100],
                    "tickmode": "array",
                    "tickvals": [0, 25, 50, 75, 100],
                    "ticksuffix": "%",
                    "tickcolor": "#9bb0c5",
                    "tickfont": {"color": "#c4d2e2", "size": 11},
                },
                "bar": {"color": color, "thickness": 0.28},
                "bgcolor": "#111f30",
                "bordercolor": "#2b4055",
                "borderwidth": 1,
                "steps": [
                    {"range": [0, 35], "color": "#163a36"},
                    {"range": [35, 70], "color": "#40351f"},
                    {"range": [70, 100], "color": "#40252c"},
                ],
            },
        )
    )

    fig.update_layout(
        height=310,
        autosize=True,
        margin=dict(l=25, r=25, t=70, b=25),
        paper_bgcolor="rgba(0,0,0,0)",
        font_color="#e6edf7",
    )
    return fig


def risk_color(level):
    return {
        "High": "#ef6464",
        "Medium": "#f3b94f",
        "Low": "#37d6a0",
        "Invalid": "#94a3b8",
    }.get(level, "#94a3b8")


# ---------- SIDEBAR ----------
with st.sidebar:
    st.markdown("## 🛡️ PhishGuard AI")
    st.caption("THREAT INTELLIGENCE CONSOLE")
    st.divider()

    page = st.radio(
        "NAVIGATION",
        ["Overview", "URL Scanner", "Batch Scanner", "Analytics", "About"],
        label_visibility="visible",
    )

    st.divider()
    st.markdown("**SYSTEM STATUS**")
    st.success("Dashboard online")

    st.caption("Local analysis only")
    st.caption("Submitted URLs are not visited by this app.")


# ---------- HEADER ----------
st.markdown(
    """
    <div class="hero">
        <div class="eyebrow">CYBERSECURITY • MACHINE LEARNING</div>
        <h1>PhishGuard <span style="color:#45e0b1">AI</span></h1>
        <p>Analyze suspicious links. Understand risk signals. Make more informed decisions.</p>
    </div>
    """,
    unsafe_allow_html=True,
)


# ---------- OVERVIEW ----------
if page == "Overview":
    history = st.session_state.scan_history
    total = len(history)
    flagged = sum(item["prediction"] == "phishing" for item in history)
    high_risk = sum(item["risk_level"] == "High" for item in history)

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("URLs Analyzed", total)
    col2.metric("ML Phishing Predictions", flagged)
    col3.metric("High Heuristic Risk", high_risk)
    col4.metric("Model", "TF-IDF + LR")
    
    st.markdown("### Quick scan")

    with st.form("overview_quick_scan"):
        quick_url = st.text_input(
            "Enter a URL",
            placeholder="https://example.com/login",
            key="overview_url_input",
        )
        quick_submit = st.form_submit_button(
            "⚡ Scan URL now",
            type="primary",
            use_container_width=True,
        )

    if quick_submit:
        if not quick_url.strip():
            st.warning("Please enter a URL first.")
        else:
            try:
                quick_heuristic = analyze_url(quick_url)
                quick_ml = predict_url(quick_url)

                quick_record = {
                    "url": quick_heuristic["url"],
                    "hostname": quick_heuristic["hostname"],
                    "risk_score": quick_heuristic["risk_score"],
                    "risk_level": quick_heuristic["risk_level"],
                    "prediction": quick_ml["prediction"],
                    "phishing_probability": quick_ml["phishing_probability"],
                    "indicators": "; ".join(
                        quick_heuristic["indicators"]
                    ),
                }

                st.session_state.scan_history.append(quick_record)
                st.session_state.latest_scan = quick_record

                
                st.success(
                    f"Scan complete: {quick_ml['prediction'].upper()} prediction."
                )

                r1, r2, r3 = st.columns(3)
                r1.metric(
                    "Heuristic risk score",
                    f"{quick_heuristic['risk_score']}/100",
                )
                r2.metric(
                    "Phishing probability",
                    f"{quick_ml['phishing_probability'] * 100:.2f}%",
                )
                r3.metric(
                    "Heuristic risk level",
                    quick_heuristic["risk_level"],
                )

                st.markdown("**URL analyzed**")
                st.code(quick_heuristic["url"], language=None)

                with st.expander("View suspicious indicators"):
                    if quick_heuristic["indicators"]:
                        for indicator in quick_heuristic["indicators"]:
                            st.write(f"• {indicator}")
                    else:
                        st.write("No heuristic indicators were detected.")


            except (ValueError, FileNotFoundError) as exc:
                st.error(str(exc))

    st.markdown("### Threat monitoring")
    left, right = st.columns([1.35, 1])

    with left:
        
        st.subheader("Recent scan activity")

        if history:
            recent = pd.DataFrame(history[-10:]).iloc[::-1]
            recent = recent[
                ["url", "prediction", "risk_level", "phishing_probability"]
            ]
            recent["phishing_probability"] = (
                recent["phishing_probability"] * 100
            ).round(2).astype(str) + "%"
            st.dataframe(recent, use_container_width=True, hide_index=True)
        else:
            st.info("No scans in this session yet. Open URL Scanner to begin.")
        

    with right:
        
        st.subheader("Session prediction mix")
        if history:
            counts = pd.Series(
                [item["prediction"] for item in history]
            ).value_counts()
            fig = px.pie(
                values=counts.values,
                names=counts.index,
                hole=0.68,
                color=counts.index,
                color_discrete_map={
                    "phishing": "#ef6464",
                    "legitimate": "#37d6a0",
                },
            )
            fig.update_layout(
                height=300,
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#dce7f3",
                legend_title_text="Prediction",
                margin=dict(l=10, r=10, t=10, b=10),
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Your prediction chart will appear after your first scan.")
        
    st.caption(
        "Metrics reflect scans performed during this browser session only. "
        "They are not global threat-intelligence statistics."
    )


# ---------- SINGLE URL SCANNER ----------
elif page == "URL Scanner":
    st.subheader("🔎 URL threat scanner")
    st.write("Enter a URL to inspect its text patterns and ML classification.")

    with st.form("url_scan_form"):
        url = st.text_input(
            "URL to analyze",
            placeholder="https://example.com/login",
        )
        submitted = st.form_submit_button(
            "⚡ Analyze URL",
            type="primary",
            use_container_width=True,
        )

    if submitted:
        if not url.strip():
            st.error("Enter a URL before starting the scan.")
        else:
            try:
                heuristic = analyze_url(url)
                ml_result = predict_url(url)

                record = {
                    "url": heuristic["url"],
                    "hostname": heuristic["hostname"],
                    "risk_score": heuristic["risk_score"],
                    "risk_level": heuristic["risk_level"],
                    "prediction": ml_result["prediction"],
                    "phishing_probability": ml_result["phishing_probability"],
                    "indicators": "; ".join(heuristic["indicators"]),
                }

                st.session_state.scan_history.append(record)
                st.session_state.latest_scan = record

            except (ValueError, FileNotFoundError) as exc:
                st.error(str(exc))

    result = st.session_state.get("latest_scan")

    if result:
        st.divider()
        st.markdown("### Analysis report")

        
        prediction = result["prediction"].lower()
        is_phishing = prediction == "phishing"

        verdict_color = "#ff5c70" if is_phishing else "#2dd4a7"
        verdict_background = "#301923" if is_phishing else "#0c2928"

        verdict_title = (
            "⚠️ Potential phishing"
            if is_phishing
            else "✓ Legitimate-like URL"
        )

        verdict_text = (
            "Potential phishing patterns detected. Treat this URL with caution."
            if is_phishing
            else "The model considers this URL more similar to legitimate examples."
        )

        st.markdown(
            f"""
            <div style="
                background:{verdict_background};
                border:1px solid {verdict_color};
                border-radius:14px;
                padding:20px 24px;
                margin:12px 0 24px 0;
            ">
                <div style="color:{verdict_color};font-size:13px;
                    font-weight:700;letter-spacing:2px;">
                    MACHINE LEARNING VERDICT
                </div>
                <div style="color:#e6edf7;font-size:25px;
                    font-weight:700;margin-top:8px;">
                    {verdict_title}
                </div>
                <div style="color:#c4d2e2;font-size:15px;margin-top:8px;">
                    {verdict_text}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        c1, c2 = st.columns([1.15, 1])
        
        
        with c1:
            st.subheader("URL details")
            
            st.markdown(
                f"""
                <div style="
                    background:#0b1928;
                    border:1px solid #30445a;
                    border-radius:12px;
                    padding:16px;
                    color:#e6edf7;
                    overflow-wrap:anywhere;
                    font-family:monospace;
                    font-size:15px;
                    margin-bottom:16px;
                ">
                    {result["url"]}
                </div>
                """,
                unsafe_allow_html=True,
            )

            st.metric(
                "Heuristic risk score",
                f'{result["risk_score"]}/100',
            )

            st.markdown(
                f'**Heuristic risk level:** '
                f'<span style="color:{risk_color(result["risk_level"])}">'
                f'{result["risk_level"]}</span>',
                unsafe_allow_html=True,
            )

            st.markdown("**Suspicious indicators**")
            if result["indicators"]:
                for indicator in result["indicators"].split("; "):
                    st.write(f"• {indicator}")
            else:
                st.write("No heuristic indicators were triggered.")

        with c2:
            st.subheader("Phishing probability")
            st.plotly_chart(
                make_gauge(result["phishing_probability"]),
                use_container_width=True,
                config={"displayModeBar": False},
            )
            st.caption(
                "Model estimate only — not proof that a URL is safe or malicious."
            )


        with st.expander("How to interpret this result"):
            st.write(
                "The heuristic analyzer checks URL patterns and calculates "
                "a separate risk score. The ML model classifies URL text "
                "based on patterns learned from its training dataset."
            )
            st.write(
                "These methods can disagree. Neither result proves that a "
                "website is safe or malicious. This application does not "
                "visit the URL."
            )


# ---------- BATCH SCANNER ----------
elif page == "Batch Scanner":
    st.subheader("📂 Batch URL scanner")
    st.write("Upload a CSV with a column named `url`.")

    uploaded = st.file_uploader(
        "Choose URL CSV",
        type=["csv"],
        help="The CSV must contain a url column.",
    )

    if uploaded is not None:
        try:
            source = pd.read_csv(uploaded)
            if "url" not in source.columns:
                st.error("The uploaded CSV must contain a 'url' column.")
            elif st.button("Scan all URLs", type="primary"):
                with st.spinner("Analyzing URL text..."):
                    st.session_state.batch_results = scan_urls(
                        source["url"].fillna("").astype(str).tolist()
                    )
        except (ValueError, pd.errors.ParserError) as exc:
            st.error(f"Could not read the CSV: {exc}")

    results = st.session_state.batch_results

    if results is not None:
        results = results.copy()

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("URLs processed", len(results))
        c2.metric(
            "ML phishing predictions",
            int((results["ml_prediction"] == "phishing").sum()),
        )
        c3.metric(
            "High heuristic risk",
            int((results["risk_level"] == "High").sum()),
        )
        c4.metric(
            "Invalid URLs",
            int((results["risk_level"] == "Invalid").sum()),
        )

        st.markdown("### Filter results")
        f1, f2, f3 = st.columns(3)

        with f1:
            risk_filter = st.multiselect(
                "Heuristic risk",
                sorted(results["risk_level"].dropna().unique()),
                default=sorted(results["risk_level"].dropna().unique()),
            )
        with f2:
            ml_filter = st.multiselect(
                "ML prediction",
                sorted(results["ml_prediction"].dropna().unique()),
                default=sorted(results["ml_prediction"].dropna().unique()),
            )
        with f3:
            search_text = st.text_input("Search URL", placeholder="Type to filter")

        filtered = results[
            results["risk_level"].isin(risk_filter)
            & results["ml_prediction"].isin(ml_filter)
        ]
        if search_text.strip():
            filtered = filtered[
                filtered["url"].str.contains(
                    search_text.strip(), case=False, na=False, regex=False
                )
            ]

        st.dataframe(
            filtered,
            use_container_width=True,
            hide_index=True,
            column_config={
                "phishing_probability": st.column_config.NumberColumn(
                    "Phishing probability",
                    format="%.2f%%",
                    help="Stored as a 0–1 probability; use the CSV for raw values.",
                )
            },
        )

        download_data = results.to_csv(index=False).encode("utf-8")
        st.download_button(
            "⬇️ Download complete CSV report",
            data=download_data,
            file_name="phishguard_scan_report.csv",
            mime="text/csv",
        )


# ---------- ANALYTICS ----------

elif page == "Analytics":
    st.subheader("📊 Scan analytics")
    st.caption("Interactive insights from scans in the current session.")

    history = st.session_state.scan_history

    if not history:
        st.info(
            "No scan history yet. Use URL Scanner or Quick Scan "
            "to generate analytics."
        )
    else:
        df = pd.DataFrame(history)

        # Ensure expected columns exist for older session records.
        for column, default in [
            ("risk_score", 0),
            ("risk_level", "Unknown"),
            ("prediction", "Unknown"),
            ("phishing_probability", 0.0),
            ("url", ""),
        ]:
            if column not in df.columns:
                df[column] = default

        total_scans = len(df)
        phishing_count = int(
            (df["prediction"].astype(str).str.lower() == "phishing").sum()
        )
        high_risk_count = int(
            (df["risk_level"].astype(str).str.lower() == "high").sum()
        )
        avg_probability = float(df["phishing_probability"].mean() * 100)

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total scans", total_scans)
        m2.metric("Phishing predictions", phishing_count)
        m3.metric("High heuristic risk", high_risk_count)
        m4.metric("Average phishing probability", f"{avg_probability:.2f}%")

        st.divider()

        # Prediction distribution
        a, b = st.columns(2)

        with a:
            prediction_counts = (
                df["prediction"]
                .astype(str)
                .str.lower()
                .value_counts()
                .rename_axis("Prediction")
                .reset_index(name="Count")
            )

            
            fig_prediction = px.pie(
                prediction_counts,
                names="Prediction",
                values="Count",
                title="Prediction distribution",
                hole=0.55,
                color="Prediction",
                color_discrete_map={
                    "phishing": "#ff5c70",
                    "legitimate": "#2dd4a7",
                    "unknown": "#8b9bb0",
                },
            )

            fig_prediction.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#e6edf7", size=13),
                title_font=dict(color="#f4f8ff", size=20),
                legend=dict(
                    font=dict(color="#c4d2e2"),
                    bgcolor="rgba(0,0,0,0)",
                ),
                legend_title_text="",
            )

            st.plotly_chart(
                fig_prediction,
                use_container_width=True,
                config={"displayModeBar": False},
            )


        with b:
            risk_counts = (
                df["risk_level"]
                .astype(str)
                .value_counts()
                .rename_axis("Risk level")
                .reset_index(name="Count")
            )

            fig_risk = px.bar(
                risk_counts,
                x="Risk level",
                y="Count",
                title="Heuristic risk levels",
                color="Risk level",
                color_discrete_map={
                    "Low": "#2dd4a7",
                    "Medium": "#ffbd4a",
                    "High": "#ff5c70",
                    "Invalid": "#8b9bb0",
                    "Unknown": "#8b9bb0",
                },
            )
            fig_risk.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#dce7f3",
                showlegend=False,
                xaxis_title="Risk level",
                yaxis_title="Number of scans",
            )
            st.plotly_chart(
                fig_risk,
                use_container_width=True,
                config={"displayModeBar": False},
            )

        # Risk score distribution
        fig_histogram = px.histogram(
            df,
            x="risk_score",
            nbins=10,
            title="Heuristic risk score distribution",
            color_discrete_sequence=["#35cba2"],
        )
        fig_histogram.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#dce7f3",
            xaxis_title="Heuristic risk score",
            yaxis_title="Number of scans",
        )
        st.plotly_chart(
            fig_histogram,
            use_container_width=True,
            config={"displayModeBar": False},
        )

        # Probability by URL
        probability_df = df.copy()
        probability_df["phishing_probability_pct"] = (
            pd.to_numeric(
                probability_df["phishing_probability"],
                errors="coerce",
            ).fillna(0) * 100
        )
        probability_df["short_url"] = probability_df["url"].apply(
            lambda value: (
                str(value)[:45] + "…"
                if len(str(value)) > 45
                else str(value)
            )
        )

        fig_probability = px.bar(
            probability_df,
            x="short_url",
            y="phishing_probability_pct",
            color="prediction",
            title="Model-estimated phishing probability by URL",
            hover_data=["url", "prediction", "risk_level"],
            color_discrete_map={
                "phishing": "#ff5c70",
                "legitimate": "#2dd4a7",
                "unknown": "#8b9bb0",
            },
        )
        fig_probability.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#dce7f3",
            xaxis_title="Scanned URL",
            yaxis_title="Estimated phishing probability (%)",
            yaxis_range=[0, 100],
        )
        st.plotly_chart(
            fig_probability,
            use_container_width=True,
            config={"displayModeBar": False},
        )

        st.subheader("Scan history")
        display_columns = [
            column for column in [
                "url",
                "prediction",
                "risk_score",
                "risk_level",
                "phishing_probability",
            ]
            if column in df.columns
        ]
        st.dataframe(
            df[display_columns],
            use_container_width=True,
            hide_index=True,
        )

        st.download_button(
            "Download analytics as CSV",
            data=df.to_csv(index=False).encode("utf-8"),
            file_name="phishguard_analytics.csv",
            mime="text/csv",
        )

    
        with b:
            fig = px.scatter(
                df,
                x="risk_score",
                y="phishing_probability",
                color="prediction",
                hover_data=["url", "risk_level"],
                title="Heuristic score vs ML probability",
                color_discrete_map={
                    "phishing": "#ef6464",
                    "legitimate": "#37d6a0",
                },
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#dce7f3",
                yaxis_tickformat=".0%",
            )
            st.plotly_chart(fig, use_container_width=True)

        st.download_button(
            "Download session history",
            data=df.to_csv(index=False).encode("utf-8"),
            file_name="phishguard_session_history.csv",
            mime="text/csv",
        )


# ---------- ABOUT ----------
elif page == "About":
    st.subheader("About PhishGuard AI")

    st.markdown(
        """
        <div class="panel">
            <h3>Explainable URL risk analysis</h3>
            <p class="muted">
                PhishGuard AI combines URL heuristics with a character-level
                TF-IDF and Logistic Regression classifier.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("**Technology stack**")
    st.write(
        "Python · Streamlit · Plotly · Pandas · Scikit-learn · "
        "FastAPI · Pytest"
    )

    st.markdown("**Model evaluation**")
    st.write(
        "The development model achieved 96.92% accuracy on a stratified "
        "random holdout from its development dataset. This does not guarantee "
        "performance on new domains or future phishing campaigns."
    )

    st.warning(
        "PhishGuard AI analyzes URL text only. It does not visit websites "
        "and should not be used as the sole security control."
    )


st.markdown("---")
st.caption(
    "PHISHGUARD AI • Local threat analysis • Predictions are estimates, not guarantees"
)
