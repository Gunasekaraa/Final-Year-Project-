import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

def visualize_cisco_data(df, return_fig=False):
    """
    Generate visualizations for Cisco vulnerability data.
    
    Args:
        df (pandas.DataFrame): The DataFrame containing Cisco vulnerability data.
        return_fig (bool): If True, return the figures instead of displaying them.
    
    Returns:
        list: A list of Plotly figures [fig_histogram, fig_bar] (if return_fig is True).
    """
    if df.empty:
        if not return_fig:
            st.warning("No data available to visualize.")
        return [None, None]

    # Convert last_updated to datetime
    try:
        df["last_updated"] = pd.to_datetime(df["last_updated"], format="%Y %b %d", errors="coerce")
        if df["last_updated"].isna().all():
            if not return_fig:
                st.warning("No valid dates in 'last_updated' column for visualization.")
            return [None, None]
    except Exception as e:
        if not return_fig:
            st.error(f"Error parsing dates: {e}")
        return [None, None]

    # --- Summary Metric: Total Vulnerabilities ---
    if not return_fig:
        st.subheader("Summary")
        total_vulnerabilities = len(df)
        st.metric("Total Vulnerabilities for Cisco", total_vulnerabilities)

    # --- Histogram: Vulnerabilities Over Time ---
    fig_histogram = px.histogram(
        df,
        x="last_updated",
        nbins=20,
        title="Distribution of Vulnerabilities Over Time",
        color_discrete_sequence=px.colors.sequential.Viridis
    )
    fig_histogram.update_layout(
        xaxis_title="Last Updated Date",
        yaxis_title="Number of Vulnerabilities",
        title_x=0.5,
        margin=dict(t=50),
        template="plotly_dark",
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
    )
    fig_histogram.update_traces(
        marker_line_color="#ffffff",
        marker_line_width=1.5,
        opacity=0.9
    )

    # --- Bar Chart: Vulnerability Count by Severity ---
    # The 'description' column contains the severity (e.g., "Critical", "High")
    severity_counts = df["description"].value_counts().reset_index()
    severity_counts.columns = ["Severity", "Count"]
    
    # Define a color map for severities
    severity_colors = {
        "Critical": "red",
        "High": "orange",
        "Medium": "yellow",
        "Informational": "blue"
    }
    colors = [severity_colors.get(severity, "gray") for severity in severity_counts["Severity"]]
    
    fig_bar = go.Figure(
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
    fig_bar.update_layout(
        title="Vulnerability Count by Severity",
        xaxis_title="Number of Vulnerabilities",
        yaxis_title="Severity",
        title_x=0.5,
        margin=dict(t=50),
        template="plotly_dark",
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
    )

    if return_fig:
        return [fig_histogram, fig_bar]
    else:
        st.subheader("Vulnerabilities Over Time")
        st.plotly_chart(fig_histogram, use_container_width=True)
        st.subheader("Vulnerability Count by Severity")
        st.plotly_chart(fig_bar, use_container_width=True)
        return None