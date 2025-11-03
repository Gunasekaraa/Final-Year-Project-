import pandas as pd
import streamlit as st
import plotly.express as px
import logging

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    filename="app.log",
    filemode="a",
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def visualize_data(data, st_instance):
    """Generate interactive visualizations for the vulnerabilities DataFrame using Plotly Express."""
    logging.info("Entering visualize_data function")

    if data.empty:
        st_instance.warning("⚠️ No data available for visualization.")
        logging.warning("DataFrame is empty")
        return

    # Log the DataFrame columns and a sample of the data
    logging.info(f"DataFrame columns: {data.columns.tolist()}")
    logging.info(f"DataFrame head: \n{data.head().to_string()}")

    # Normalize column names for consistency
    data.columns = data.columns.str.lower().str.replace(" ", "_")
    logging.info(f"Normalized DataFrame columns: {data.columns.tolist()}")

    st_instance.header("📈 Vulnerability Insights Dashboard")

    # Layout: Two columns for bar chart and pie chart, histogram below
    col1, col2 = st_instance.columns(2)

    # Bar Chart: Vulnerabilities by Product Name
    with col1:
        st_instance.subheader("📊 Vulnerabilities by Product Name")
        if "product_name" in data.columns:
            try:
                product_counts = data["product_name"].value_counts().reset_index()
                product_counts.columns = ["product_name", "count"]
                logging.info(f"Product counts: \n{product_counts.to_string()}")

                fig = px.bar(
                    product_counts,
                    x="count",
                    y="product_name",
                    orientation="h",
                    color="product_name",
                    color_discrete_sequence=px.colors.qualitative.Pastel,
                    title="Vulnerabilities by Product Name"
                )
                fig.update_layout(
                    xaxis_title="Number of Vulnerabilities",
                    yaxis_title="Product Name",
                    showlegend=False,
                    title_x=0.5,
                    margin=dict(t=50),
                    plot_bgcolor="rgba(0,0,0,0)",
                    paper_bgcolor="rgba(0,0,0,0)",
                    font=dict(color="#ffffff")
                )
                fig.update_traces(
                    marker_line_color="#ffffff",
                    marker_line_width=1.5,
                    opacity=0.9
                )
                st_instance.plotly_chart(fig, use_container_width=True)
                logging.info("Bar chart rendered successfully")
            except Exception as e:
                st_instance.warning(f"⚠️ Error generating bar chart: {e}")
                logging.error(f"Error generating bar chart: {e}")
        else:
            st_instance.warning("⚠️ 'product_name' column not found in the DataFrame.")
            logging.warning("'product_name' column not found")

    # Pie Chart: Vulnerabilities by Severity Level
    with col2:
        st_instance.subheader("📊 Vulnerabilities by Severity Level")
        if "severity_level" in data.columns:
            try:
                severity_counts = data["severity_level"].value_counts().reset_index()
                severity_counts.columns = ["severity_level", "count"]
                logging.info(f"Severity counts: \n{severity_counts.to_string()}")

                # Updated color palette for severity levels (muted tones for dark theme)
                severity_colors = {
                    "critical": "#ff6b6b",  # Soft Red
                    "high": "#ff9f43",      # Soft Orange
                    "medium": "#feca57",    # Soft Yellow
                    "low": "#48cae4",      # Soft Blue
                    "informational": "#adb5bd",  # Light Gray
                    "n/a": "#6c757d"       # Muted Gray
                }
                fig = px.pie(
                    severity_counts,
                    values="count",
                    names="severity_level",
                    color="severity_level",
                    color_discrete_map=severity_colors,
                    title="Vulnerabilities by Severity Level"
                )
                fig.update_traces(
                    textinfo="percent+label",
                    textposition="inside",
                    marker=dict(line=dict(color="#ffffff", width=1.5))
                )
                fig.update_layout(
                    title_x=0.5,
                    margin=dict(t=50),
                    plot_bgcolor="rgba(0,0,0,0)",
                    paper_bgcolor="rgba(0,0,0,0)",
                    font=dict(color="#ffffff"),
                    legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5)
                )
                st_instance.plotly_chart(fig, use_container_width=True)
                logging.info("Pie chart rendered successfully")
            except Exception as e:
                st_instance.warning(f"⚠️ Error generating pie chart: {e}")
                logging.error(f"Error generating pie chart: {e}")
        else:
            st_instance.warning("⚠️ 'severity_level' column not found in the DataFrame.")
            logging.warning("'severity_level' column not found")

    # Histogram: Vulnerabilities Over Time (Published Date)
    st_instance.subheader("📊 Vulnerabilities Over Time")
    if "published_date" in data.columns:
        try:
            # Ensure Published Date is in datetime format
            data["published_date"] = pd.to_datetime(data["published_date"], errors="coerce")
            if data["published_date"].isna().all():
                st_instance.warning("⚠️ No valid dates in 'published_date' column.")
                logging.warning("No valid dates in 'published_date' column")
                return

            fig = px.histogram(
                data,
                x="published_date",
                nbins=20,
                title="Distribution of Vulnerabilities Over Time",
                color_discrete_sequence=px.colors.sequential.Viridis
            )
            fig.update_layout(
                xaxis_title="Published Date",
                yaxis_title="Number of Vulnerabilities",
                title_x=0.5,
                margin=dict(t=50),
                plot_bgcolor="rgba(0,0,0,0)",
                paper_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#ffffff")
            )
            fig.update_traces(
                marker_line_color="#ffffff",
                marker_line_width=1.5,
                opacity=0.9
            )
            st_instance.plotly_chart(fig, use_container_width=True)
            logging.info("Histogram rendered successfully")
        except Exception as e:
            st_instance.warning(f"⚠️ Error generating histogram: {e}")
            logging.error(f"Error generating histogram: {e}")
    else:
        st_instance.warning("⚠️ 'published_date' column not found in the DataFrame.")
        logging.warning("'published_date' column not found")