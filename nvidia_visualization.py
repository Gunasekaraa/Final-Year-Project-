import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
import logging

# Ensure logging is set up
logging.basicConfig(
    level=logging.DEBUG,
    filename="app.log",
    filemode="a",
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def visualize_nvidia_vulnerabilities(df, return_fig=True):
    """
    Generate visualizations for NVIDIA vulnerability data.
    
    Args:
        df (pandas.DataFrame): The DataFrame containing NVIDIA vulnerability data.
        return_fig (bool): If True, return the figures instead of displaying them. Defaults to True.
    
    Returns:
        list: A list of Plotly figures [fig1, fig2, fig3].
              fig1: Line chart (Vulnerabilities Over Time) or None if published_date is missing.
              fig2: Bar chart (Vulnerability Count by Severity) or None if severity_level is missing.
              fig3: Pie chart (Severity Distribution) or None if severity_level is missing.
    """
    if df.empty:
        logging.warning("DataFrame is empty in visualize_nvidia_vulnerabilities.")
        if not return_fig:
            st.warning("No data available to visualize.")
        return [None, None, None]

    # Log the DataFrame for debugging
    logging.info(f"DataFrame columns in visualize_nvidia_vulnerabilities: {df.columns.tolist()}")
    logging.info(f"DataFrame head:\n{df.head().to_string()}")

    # Initialize figures
    fig1, fig2, fig3 = None, None, None

    # Line Chart: Vulnerabilities Over Time (requires published_date)
    if "published_date" in df.columns:
        # Ensure published_date is a string and handle missing values
        df["published_date"] = df["published_date"].astype(str).replace("nan", "N/A").replace("", "N/A")
        logging.info(f"Unique values in published_date: {df['published_date'].dropna().unique().tolist()}")

        vuln_counts = df.groupby("published_date").size().reset_index(name="count")
        logging.info(f"Vulnerabilities over time (vuln_counts):\n{vuln_counts.to_string()}")

        if not vuln_counts.empty:
            fig1 = px.line(
                vuln_counts,
                x="published_date",
                y="count",
                title="Vulnerabilities Over Time",
                markers=True,
                color_discrete_sequence=["#00CC96"]
            )
            fig1.update_layout(
                xaxis_title="Published Date",
                yaxis_title="Number of Vulnerabilities",
                title_x=0.5,
                template="plotly_dark",
                plot_bgcolor="rgba(0,0,0,0)",
                paper_bgcolor="rgba(0,0,0,0)",
            )
            # Rotate x-axis labels if there are many unique dates
            fig1.update_xaxes(tickangle=45)
        else:
            logging.warning("No data available for line chart after grouping by published_date.")
    else:
        logging.warning("No 'published_date' column found in DataFrame. Skipping line chart.")

    # Bar Chart: Vulnerability Count by Severity (requires severity_level)
    if "severity_level" in df.columns:
        severity_counts = df["severity_level"].value_counts().reset_index()
        severity_counts.columns = ["Severity", "Count"]
        logging.info(f"Severity counts:\n{severity_counts.to_string()}")

        severity_colors = {
            "critical": "red",
            "high": "orange",
            "medium": "yellow",
            "low": "blue",
            "informational": "cyan",
            "n/a": "gray"
        }
        colors = [severity_colors.get(severity.lower(), "gray") for severity in severity_counts["Severity"]]
        fig2 = go.Figure(
            data=[
                go.Bar(
                    x=severity_counts["Count"],
                    y=severity_counts["Severity"],
                    orientation="h",
                    marker_color=colors,
                    text=severity_counts["Count"],
                    textposition="auto"
                )
            ]
        )
        fig2.update_layout(
            title="Vulnerability Count by Severity",
            xaxis_title="Number of Vulnerabilities",
            yaxis_title="Severity",
            title_x=0.5,
            template="plotly_dark",
            plot_bgcolor="rgba(0,0,0,0)",
            paper_bgcolor="rgba(0,0,0,0)",
        )
    else:
        logging.warning("No 'severity_level' column found in DataFrame. Skipping bar chart.")

    # Pie Chart: Severity Distribution (requires severity_level)
    if "severity_level" in df.columns and not severity_counts.empty:
        fig3 = px.pie(
            severity_counts,
            names="Severity",
            values="Count",
            title="Severity Distribution",
            color="Severity",
            color_discrete_map=severity_colors
        )
        fig3.update_layout(
            title_x=0.5,
            template="plotly_dark",
            plot_bgcolor="rgba(0,0,0,0)",
            paper_bgcolor="rgba(0,0,0,0)",
        )
    else:
        logging.warning("Skipping pie chart due to missing severity_level column or empty severity_counts.")

    # Log the status of the figures
    logging.info(f"Figures generated - fig1: {fig1 is not None}, fig2: {fig2 is not None}, fig3: {fig3 is not None}")

    return [fig1, fig2, fig3]