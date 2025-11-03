import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', filename="visualization.log")

def visualize_dell_vulnerabilities(df):
    """
    Visualize Dell vulnerability data using Plotly.

    Parameters:
    df (pd.DataFrame): DataFrame with columns: vulnerability, description, published_date, unique_id, last_updated
    """
    try:
        # Validate DataFrame
        required_columns = ['vulnerability', 'description', 'published_date', 'unique_id', 'last_updated']
        if not all(col in df.columns for col in required_columns):
            missing = [col for col in required_columns if col not in df.columns]
            logging.error(f"Missing required columns: {missing}")
            return

        if df.empty:
            logging.warning("DataFrame is empty. No data to visualize.")
            return

        # Clean and preprocess data
        df = df.copy()
        
        # Extract severity from description
        df['severity'] = df['description'].str.extract(r'(Critical|High|Medium|Low)', expand=False)
        df['severity'] = df['severity'].fillna('Unknown')
        
        # Convert date columns to datetime
        df['published_date'] = pd.to_datetime(df['published_date'], format='%b %d %Y', errors='coerce')
        df['last_updated'] = pd.to_datetime(df['last_updated'], format='%b %d %Y', errors='coerce')

        # Log any rows with invalid dates
        if df['published_date'].isna().any() or df['last_updated'].isna().any():
            logging.warning("Some dates could not be parsed. Check data format.")

        # 1. Pie Chart: Severity Distribution
        severity_counts = df['severity'].value_counts().reset_index()
        severity_counts.columns = ['severity', 'count']
        fig1 = px.pie(
            severity_counts,
            names='severity',
            values='count',
            title='Distribution of Dell Vulnerability Severity Levels',
            color_discrete_sequence=px.colors.qualitative.Set2
        )
        fig1.update_layout(showlegend=True)
        fig1.write_html("dell_severity_distribution.html")
        logging.info("Generated severity distribution pie chart.")

        # 2. Bar Chart: Vulnerabilities by Published Month
        df['published_month'] = df['published_date'].dt.to_period('M').astype(str)
        month_counts = df['published_month'].value_counts().sort_index().reset_index()
        month_counts.columns = ['published_month', 'count']
        fig2 = px.bar(
            month_counts,
            x='published_month',
            y='count',
            title='Dell Vulnerabilities Published by Month',
            labels={'published_month': 'Month', 'count': 'Number of Vulnerabilities'},
            color_discrete_sequence=px.colors.qualitative.Set2
        )
        fig2.update_layout(xaxis_tickangle=-45)
        fig2.write_html("dell_published_timeline.html")
        logging.info("Generated published timeline bar chart.")

        # 3. Scatter Plot: Published Date vs Last Updated
        fig3 = px.scatter(
            df,
            x='published_date',
            y='last_updated',
            color='severity',
            size=df['severity'].map({'Low': 10, 'Medium': 20, 'High': 30, 'Critical': 40, 'Unknown': 15}),
            hover_data=['vulnerability', 'unique_id'],
            title='Published Date vs Last Updated for Dell Vulnerabilities',
            labels={'published_date': 'Published Date', 'last_updated': 'Last Updated Date'},
            color_discrete_sequence=px.colors.qualitative.Set2
        )
        fig3.update_layout(showlegend=True)
        fig3.write_html("dell_published_vs_updated.html")
        logging.info("Generated published vs updated scatter plot.")

        return fig1, fig2, fig3  # Return figures for Streamlit rendering

    except Exception as e:
        logging.error(f"Error during visualization: {e}")
        return None, None, None

# Example usage with real-time data from scraper
if __name__ == "__main__":
    from scraper import scrape_vulnerabilities  # Adjust import based on your project structure
    try:
        # Fetch real-time Dell data
        url = "https://www.dell.com/support/kbdoc/en-us"
        df = scrape_vulnerabilities(url)
        fig1, fig2, fig3 = visualize_dell_vulnerabilities(df)
        if fig1 and fig2 and fig3:
            fig1.show()
            fig2.show()
            fig3.show()
    except Exception as e:
        logging.error(f"Failed to fetch or visualize data: {e}")