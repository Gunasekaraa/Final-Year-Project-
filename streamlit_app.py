import streamlit as st
st.set_page_config(page_title="Automated Vulnerability Tracker", page_icon="🔒", layout="wide")

import os
import sys
import logging
import django
import requests
import pandas as pd
import numpy as np
from dotenv import load_dotenv
import re
import nltk
from nltk.tokenize import word_tokenize
from nltk.tag import pos_tag
from datetime import datetime
import traceback

# Download NLTK data
try:
    nltk.data.find('tokenizers/punkt_tab')
    nltk.data.find('taggers/averaged_perceptron_tagger_eng')
except LookupError:
    nltk.download('punkt_tab')
    nltk.download('averaged_perceptron_tagger_eng')

# Load environment variables
load_dotenv()
EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

# Logging Setup
logging.basicConfig(
    level=logging.DEBUG,
    filename="app.log",
    filemode="w",
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logging.debug("Environment variables loaded.")

# Django Setup
PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
DJANGO_PROJECT_ROOT = os.path.join(PROJECT_ROOT, "scraper")
sys.path.extend([PROJECT_ROOT, DJANGO_PROJECT_ROOT, os.path.join(DJANGO_PROJECT_ROOT, "scraper_app")])
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "scraper.settings")
django.setup()

# Import Django Modules
from scraper_app.scrapers.cisco_scraper import scrape_cisco
from scraper_app.scrapers.intel_scraper import scrape_intel
from scraper_app.scrapers.adobe_scraper import scrape_adobe
from scraper_app.scrapers.nvidia_scraper import scrape_nvidia
from scraper_app.scrapers.dell_scraper import scrape_dell
from scraper_app.scrapers.paloalto_scraper import scrape_palo_alto
from scraper_app.visualization.cisco_visualization import visualize_cisco_data
from scraper_app.visualization.dell_visualization import visualize_dell_vulnerabilities
from scraper_app.visualization.nvidia_visualization import visualize_nvidia_vulnerabilities
from scraper_app.modules.authentication import signup, login, logout, is_authenticated
from scraper_app.modules.visualization import visualize_data
from scraper_app.modules.report import send_vulnerability_report

# Import Chatbots
from scraper_app.chatbot.nvidia_queries import query_nvidia_bot
from scraper_app.chatbot.palo_alto_queries import query_palo_alto_bot
from scraper_app.chatbot.cisco_queries import query_cisco_bot

# Initialize Session State
def init_state(key, default):
    if key not in st.session_state:
        st.session_state[key] = default

for key, value in {
    "authenticated": False,
    "scraped_data": None,
    "selected_oem": None,
    "user_email": None,
    "username": None,
    "token": None,
    "scan_triggered": False,
    "chat_history": []
}.items():
    init_state(key, value)

# Email Validation Function (Fixed Regex)
def is_valid_email(email):
    if not email:
        return False
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# Sidebar Navigation
with st.sidebar:
    st.image("logo.jpg.jpg", caption="🚀 Oemcrawl", width=220)
    st.markdown("---")
    st.title("🔧 Navigation")
    page = st.radio("Select Page", ["Login", "Signup", "Dashboard"])

# OEM Scraper Mapping
oem_options = {
    "NVIDIA": "https://www.nvidia.com/en-us/security/",
    "Cisco": "https://sec.cloudapps.cisco.com/security/center/publicationListing.x?product=Cisco&sort=-day_sir&limit=100#~Vulnerabilities",
    "Intel": "https://www.intel.com/content/www/us/en/security-center/default.html",
    "Adobe": "https://helpx.adobe.com/security/security-bulletin.html",
    "Dell": "https://www.dell.com/support/security/en-in",
    "Palo Alto Networks": "https://security.paloaltonetworks.com/?sort=-date&limit=100"
}
scraper_functions = {
    "NVIDIA": scrape_nvidia,
    "Cisco": scrape_cisco,
    "Intel": scrape_intel,
    "Adobe": scrape_adobe,
    "Dell": scrape_dell,
    "Palo Alto Networks": scrape_palo_alto
}

# Dashboard Page
if page == "Dashboard" and is_authenticated():
    st.sidebar.button("🚪 Logout", on_click=logout)
    st.title("📊 Vulnerability Tracker Dashboard")

    # Apply custom CSS for containers and table
    st.markdown(
        """
        <style>
        .custom-container {
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 20px;
            background-color: #f9f9f9;
        }
        .vuln-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        .vuln-table th, .vuln-table td {
            border: 1px solid #444;
            padding: 12px;
            text-align: left;
        }
        /* Dark mode styles */
        @media (prefers-color-scheme: dark) {
            .custom-container {
                background-color: #2a2a2a;
                border-color: #444;
            }
            .vuln-table th {
                background-color: #333;
                color: #fff;
                font-weight: bold;
            }
            .vuln-table td {
                background-color: #1e1e1e;
                color: #ddd;
            }
            .vuln-table tr:nth-child(even) td {
                background-color: #252525;
            }
            .vuln-table tr:hover td {
                background-color: #333;
            }
            .vuln-table a {
                color: #66b0ff;
                text-decoration: none;
            }
            .vuln-table a:hover {
                text-decoration: underline;
            }
        }
        /* Light mode styles */
        @media (prefers-color-scheme: light) {
            .custom-container {
                background-color: #f9f9f9;
                border-color: #ddd;
            }
            .vuln-table th {
                background-color: #e0e0e0;
                color: #333;
                font-weight: bold;
            }
            .vuln-table td {
                background-color: #fff;
                color: #333;
            }
            .vuln-table tr:nth-child(even) td {
                background-color: #f5f5f5;
            }
            .vuln-table tr:hover td {
                background-color: #e5e5e5;
            }
            .vuln-table a {
                color: #1a73e8;
                text-decoration: none;
            }
            .vuln-table a:hover {
                text-decoration: underline;
            }
        }
        </style>
        """,
        unsafe_allow_html=True
    )

    # Input Section
    with st.container():
        st.markdown('<div class="custom-container">', unsafe_allow_html=True)
        col1, col2 = st.columns([3, 1])
        with col1:
            st.subheader("🔍 Scan Vulnerabilities")
            selected_oem = st.selectbox("Choose an OEM", list(oem_options.keys()))
            manual_url = st.text_input("Or enter a custom URL", "")
            scan_url = manual_url or oem_options[selected_oem]
            if manual_url and manual_url != oem_options[selected_oem]:
                st.warning(f"⚠️ Using custom URL: {manual_url}. Ensure it matches the expected structure for {selected_oem}.")
        with col2:
            st.markdown("### 🛡️")
            severity_options = ["N/A", "Low", "Medium", "High", "Critical", "Informational"]
            severity_filter = st.multiselect("Filter by Severity", severity_options, default=severity_options)

        if st.button("🚀 Start Scan", use_container_width=True, key="scan_button"):
            st.session_state["scan_triggered"] = True
            st.session_state["selected_oem"] = selected_oem

        st.markdown('</div>', unsafe_allow_html=True)

    # Scan Logic
    if st.session_state.get("scan_triggered"):
        with st.spinner("Scraping in progress..."):
            if selected_oem not in scraper_functions:
                st.error(f"❌ Scraper for {selected_oem} is not supported yet. Please select a different OEM.")
            else:
                try:
                    df = scraper_functions[selected_oem](scan_url)
                    if df is None or df.empty:
                        st.warning("⚠️ No data returned from scraper. Check the logs or URL.")
                        logging.warning(f"No data returned for {selected_oem} from {scan_url}")
                    else:
                        # Normalize column names for consistency
                        df.columns = df.columns.str.lower().str.replace(" ", "_")
                        logging.info(f"DataFrame columns after normalization: {df.columns.tolist()}")
                        logging.info(f"DataFrame head:\n{df.head().to_string()}")

                        # Map possible date column names to published_date
                        date_columns = ['date', 'published', 'date_published', 'publication_date', 'release_date', 'publisheddate', 'issue_date', 'posted_date', 'posted', 'last_modified']
                        date_column_found = None
                        for col in df.columns:
                            if col in date_columns:
                                date_column_found = col
                                break
                        if date_column_found:
                            df = df.rename(columns={date_column_found: "published_date"})
                            logging.info(f"Renamed {date_column_found} to published_date")
                        else:
                            logging.warning(f"No date column found in {selected_oem} data. Expected one of {date_columns}")

                        # Force date columns to strings to prevent parsing issues
                        for date_col in ["published_date", "last_updated"]:
                            if date_col in df.columns:
                                df[date_col] = df[date_col].astype(str).replace("nan", "N/A").replace("", "N/A")
                                logging.info(f"Converted {date_col} to string. Unique values: {df[date_col].unique().tolist()}")

                        # Map possible severity-related columns for extraction
                        severity_cols = ['severity', 'impact', 'description', 'cvss_score', 'severity_rating', 'base_score', 'cvss_base_score', 'cvss']
                        severity_col_found = None
                        for col in df.columns:
                            if col in severity_cols:
                                severity_col_found = col
                                break

                        # Extract severity based on OEM
                        if "severity_level" not in df.columns:
                            severity_found = False
                            if selected_oem == "Dell" and "description" in df.columns:
                                df['severity_level'] = df['description'].str.extract(r'(Critical|High|Medium|Low|Informational)', expand=False, flags=re.IGNORECASE)
                                df['severity_level'] = df['severity_level'].fillna('N/A').str.lower()
                                logging.info("Extracted severity_level from description for Dell.")
                                severity_found = True
                            elif selected_oem == "NVIDIA" and severity_col_found:
                                # NVIDIA-specific severity extraction
                                col = severity_col_found
                                unique_vals = df[col].dropna().unique().tolist()
                                logging.info(f"Unique values in {col} for NVIDIA: {unique_vals[:10]}")
                                # Try extracting severity from text
                                df['severity_level'] = df[col].str.extract(r'(Critical|High|Medium|Low|Informational)', expand=False, flags=re.IGNORECASE)
                                if df['severity_level'].notna().any():
                                    severity_found = True
                                    logging.info(f"Extracted severity_level from {col} for NVIDIA.")
                                else:
                                    # Try extracting CVSS score and map to severity
                                    cvss_scores = df[col].str.extract(r'(?:CVSS: )?(\d+\.\d+)', expand=False).astype(float)
                                    if cvss_scores.notna().any():
                                        df['severity_level'] = cvss_scores.apply(lambda x: 'Critical' if x >= 9.0 else 'High' if x >= 7.0 else 'Medium' if x >= 4.0 else 'Low' if x > 0 else 'N/A')
                                        severity_found = True
                                        logging.info(f"Mapped CVSS scores to severity levels in {col} for NVIDIA.")
                            else:
                                for col in severity_cols:
                                    if col in df.columns:
                                        unique_vals = df[col].dropna().unique().tolist()
                                        logging.info(f"Unique values in {col} for {selected_oem}: {unique_vals[:10]}")
                                        df['severity_level'] = df[col].str.extract(r'(Critical|High|Medium|Low|Informational)', expand=False, flags=re.IGNORECASE)
                                        if df['severity_level'].notna().any():
                                            severity_found = True
                                            logging.info(f"Extracted severity_level from {col} for {selected_oem}.")
                                            break
                                        df['severity_level'] = df[col].str.extract(r'CVSS: \d+\.\d+ \((Critical|High|Medium|Low|Informational)\)', expand=False, flags=re.IGNORECASE)
                                        if df['severity_level'].notna().any():
                                            severity_found = True
                                            logging.info(f"Extracted severity_level from CVSS format in {col} for {selected_oem}.")
                                            break
                                        df['severity_level'] = df[col].str.extract(r'(?:Severity|Rating): (Critical|High|Medium|Low|Informational)', expand=False, flags=re.IGNORECASE)
                                        if df['severity_level'].notna().any():
                                            severity_found = True
                                            logging.info(f"Extracted severity_level from 'Severity/Rating:' format in {col} for {selected_oem}.")
                                            break
                                        cvss_scores = df[col].str.extract(r'(?:CVSS: )?(\d+\.\d+)', expand=False).astype(float)
                                        if cvss_scores.notna().any():
                                            df['severity_level'] = cvss_scores.apply(lambda x: 'Critical' if x >= 9.0 else 'High' if x >= 7.0 else 'Medium' if x >= 4.0 else 'Low' if x > 0 else 'N/A')
                                            severity_found = True
                                            logging.info(f"Mapped CVSS scores to severity levels in {col} for {selected_oem}.")
                                            break
                                        if selected_oem == "Cisco":
                                            df['severity_level'] = df[col].str.extract(r'(Critical|High|Medium|Low|Informational) \(CVSS \d+\.\d+\)', expand=False, flags=re.IGNORECASE)
                                            if df['severity_level'].notna().any():
                                                severity_found = True
                                                logging.info(f"Extracted severity_level from 'Severity (CVSS X.X)' format in {col} for Cisco.")
                                                break
                            if not severity_found:
                                df['severity_level'] = 'N/A'
                                logging.warning(f"Could not extract severity for {selected_oem}. Defaulting to N/A.")

                        # Apply severity filter using 'severity_level' column
                        if "severity_level" in df.columns:
                            df["severity_level"] = df["severity_level"].str.lower()
                            severity_filter_lower = [s.lower() for s in severity_filter]
                            logging.info(f"Applying severity filter: {severity_filter_lower}")
                            df = df[df["severity_level"].isin(severity_filter_lower)]
                            logging.info(f"Filtered DataFrame rows: {len(df)}")
                            logging.info(f"Severity levels after filter: {df['severity_level'].unique().tolist()}")
                            if df.empty:
                                st.warning(f"⚠️ No data remains after applying severity filter: {severity_filter}. Try adjusting the filter.")
                                logging.warning(f"No data remains after severity filter: {severity_filter}")

                        # Store and display the DataFrame
                        st.session_state["scraped_data"] = df
                        st.success("✅ Scan completed!")
                        st.dataframe(df)

                        if "scraped_data" in st.session_state and not st.session_state["scraped_data"].empty:
                            st.write(f"✅ Data scraped successfully! Rows: {len(df)}")
                            logging.info(f"Scrapped data stored successfully with {len(df)} rows")
                        else:
                            st.write("⚠️ No data scraped or DataFrame is empty.")
                            logging.warning("Scraped data is empty or not stored")

                        # Metric Cards
                        st.markdown("### 📊 Key Metrics")
                        col1, col2, col3, col4, col5 = st.columns(5)
                        total_vulns = len(df)
                        critical_count = len(df[df["severity_level"] == "critical"]) if "severity_level" in df.columns else 0
                        high_count = len(df[df["severity_level"] == "high"]) if "severity_level" in df.columns else 0
                        medium_count = len(df[df["severity_level"] == "medium"]) if "severity_level" in df.columns else 0
                        low_count = len(df[df["severity_level"] == "low"]) if "severity_level" in df.columns else 0

                        logging.info(f"Metrics - Total: {total_vulns}, Critical: {critical_count}, High: {high_count}, Medium: {medium_count}, Low: {low_count}")

                        with col1:
                            st.metric("Total Vulnerabilities", total_vulns)
                        with col2:
                            st.metric("Critical", critical_count)
                        with col3:
                            st.metric("High", high_count)
                        with col4:
                            st.metric("Medium", medium_count)
                        with col5:
                            st.metric("Low", low_count)

                        # Data Table in Expander
                        with st.expander("View Vulnerability Data"):
                            html = '<table class="vuln-table"><tr>'
                            for col in df.columns:
                                html += f'<th>{col}</th>'
                            html += '</tr>'
                            for _, row in df.iterrows():
                                html += '<tr>'
                                for col in df.columns:
                                    if col == 'url':
                                        html += f'<td><a href="{row[col]}" target="_blank">{row[col]}</a></td>'
                                    else:
                                        html += f'<td>{row[col]}</td>'
                                html += '</tr>'
                            html += '</table>'
                            st.markdown(html, unsafe_allow_html=True)
                            st.download_button("📥 Download CSV", df.to_csv(index=False), "vulnerabilities.csv", "text/csv")

                except Exception as e:
                    logging.error(f"Error scraping {selected_oem}: {str(e)}")
                    st.error(f"❌ Error scraping {selected_oem}: {str(e)}")
                finally:
                    st.session_state["scan_triggered"] = False

    # Email Report and Visualization
    if st.session_state["scraped_data"] is not None:
        if st.button("📧 Email Report", use_container_width=True):
            user_email = st.session_state.get("user_email")
            if not all([user_email, EMAIL_SENDER, EMAIL_PASSWORD]):
                st.error("Missing email credentials.")
            elif not is_valid_email(user_email):
                st.error("❌ Invalid email address in profile. Please update your email to a valid format (e.g., user@example.com).")
            else:
                # Log the DataFrame being sent to the report function
                logging.info("Preparing to send email report...")
                logging.info(f"DataFrame columns: {st.session_state['scraped_data'].columns.tolist()}")
                logging.info(f"DataFrame dtypes:\n{st.session_state['scraped_data'].dtypes}")
                success, message = send_vulnerability_report(
                    user_email,
                    st.session_state["scraped_data"],
                    EMAIL_SENDER,
                    EMAIL_PASSWORD,
                    SMTP_SERVER,
                    SMTP_PORT,
                    oem=selected_oem
                )
                if success:
                    st.success(f"✅ {message}")
                else:
                    st.error(f"❌ {message}")

        # Debug: Log DataFrame columns before visualization
        df = st.session_state["scraped_data"]
        logging.info(f"DataFrame before visualization - Rows: {len(df)}")
        logging.info(f"DataFrame columns before visualization: {df.columns.tolist()}")
        logging.info(f"DataFrame head: \n{df.head().to_string()}")
        # Additional logging for published_date
        if "published_date" in df.columns:
            logging.info(f"Unique values in published_date before visualization: {df['published_date'].dropna().unique().tolist()}")
        else:
            logging.warning("No 'published_date' column found in DataFrame before visualization.")
        with st.expander("Debug: DataFrame Before Visualization"):
            st.write(f"Rows: {len(df)}")
            st.write("Columns:", df.columns.tolist())
            if "published_date" in df.columns:
                st.write("Unique values in published_date:", df["published_date"].dropna().unique().tolist())
            else:
                st.write("⚠️ 'published_date' column is missing.")
            st.dataframe(df)

        # Visualizations Section
        st.markdown("---")
        with st.container():
            st.markdown('<div class="custom-container">', unsafe_allow_html=True)
            st.markdown("### 📈 Visualizations")
            try:
                if df.empty:
                    st.warning("⚠️ No data available to visualize after filtering.")
                    logging.info("DataFrame is empty before visualization.")
                else:
                    if selected_oem == "Cisco":
                        visualize_cisco_data(df)
                        logging.info("Called visualize_cisco_data.")
                    elif selected_oem == "Dell":
                        figs = visualize_dell_vulnerabilities(df)
                        if figs:
                            fig1, fig2, fig3 = figs
                            if fig1:
                                st.subheader("Vulnerabilities Over Time (Dell)")
                                st.plotly_chart(fig1, use_container_width=True, key="dell_fig1")
                                logging.info("Rendered fig1 for Dell.")
                            if fig2:
                                st.subheader("Vulnerability Count by Severity (Dell)")
                                st.plotly_chart(fig2, use_container_width=True, key="dell_fig2")
                                logging.info("Rendered fig2 for Dell.")
                            if fig3:
                                st.subheader("Severity Distribution (Dell)")
                                st.plotly_chart(fig3, use_container_width=True, key="dell_fig3")
                                logging.info("Rendered fig3 for Dell.")
                        else:
                            st.warning("⚠️ Unable to generate visualizations for Dell data. Check the DataFrame for required columns (e.g., published_date, severity_level).")
                            logging.info("visualize_dell_vulnerabilities returned None.")
                    elif selected_oem == "NVIDIA":
                        figs = visualize_nvidia_vulnerabilities(df, return_fig=True)
                        if figs:
                            fig1, fig2, fig3 = figs
                            if not any([fig1, fig2, fig3]):
                                st.warning("⚠️ No visualizations generated for NVIDIA data. Ensure the DataFrame contains 'published_date' and 'severity_level' columns with valid data.")
                                logging.info("visualize_nvidia_vulnerabilities returned all None figures.")
                            else:
                                if fig1:
                                    st.subheader("Vulnerabilities Over Time (NVIDIA)")
                                    st.plotly_chart(fig1, use_container_width=True, key="nvidia_fig1")
                                    logging.info("Rendered fig1 for NVIDIA.")
                                else:
                                    st.warning("⚠️ Could not generate 'Vulnerabilities Over Time' chart. Check if 'published_date' contains valid data.")
                                if fig2:
                                    st.subheader("Vulnerability Count by Severity (NVIDIA)")
                                    st.plotly_chart(fig2, use_container_width=True, key="nvidia_fig2")
                                    logging.info("Rendered fig2 for NVIDIA.")
                                else:
                                    st.warning("⚠️ Could not generate 'Vulnerability Count by Severity' chart. Check if 'severity_level' column exists.")
                                if fig3:
                                    st.subheader("Severity Distribution (NVIDIA)")
                                    st.plotly_chart(fig3, use_container_width=True, key="nvidia_fig3")
                                    logging.info("Rendered fig3 for NVIDIA.")
                                else:
                                    st.warning("⚠️ Could not generate 'Severity Distribution' chart. Check if 'severity_level' column exists.")
                        else:
                            st.warning("⚠️ Unable to generate visualizations for NVIDIA data. Check the DataFrame for required columns (e.g., published_date, severity_level).")
                            logging.info("visualize_nvidia_vulnerabilities returned None.")
                    else:
                        visualize_data(df, st)
                        logging.info("Called visualize_data for default case.")
            except Exception as e:
                st.error(f"❌ Error in visualization section: {str(e)}")
                logging.error(f"Error in visualization section: {str(e)}")
            st.markdown('</div>', unsafe_allow_html=True)

        # Rule-Based Chatbot Section
        st.markdown("---")
        with st.container():
            st.markdown('<div class="custom-container">', unsafe_allow_html=True)
            st.markdown("### 🤖 Query Your Data")
            st.info("Ask questions about your vulnerability data using simple queries like:\n"
                    "- 'Show latest 5 advisories' (NVIDIA, Palo Alto, Cisco)\n"
                    "- 'Critical severity vulnerabilities' (NVIDIA, Palo Alto, Cisco)\n"
                    "- 'CVE for specific vulnerability' (NVIDIA)\n"
                    "- 'Publish date for specific vulnerability' (NVIDIA)\n"
                    "- 'Details for CVE-2025-0128' (Palo Alto)\n"
                    "- 'Affected versions for PAN-SA-2025-0008' (Palo Alto)\n"
                    "- 'Vulnerabilities for Cisco IOS XE Software' (Cisco)\n"
                    "- 'Details for https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-fileoverwrite-Uc9tXWH' (Cisco)")
            query = st.text_input("Ask anything about the vulnerabilities:")
            if st.button("💬 Query") and query:
                try:
                    with st.spinner("Processing your query..."):
                        # Ensure date columns are strings
                        df = st.session_state["scraped_data"].copy()
                        for date_col in ["published_date", "last_updated"]:
                            if date_col in df.columns:
                                df[date_col] = df[date_col].astype(str).replace("nan", "N/A").replace("", "N/A")
                        # Route query to appropriate chatbot
                        if selected_oem == "NVIDIA":
                            # Align NVIDIA data with expected column names for query_nvidia_bot
                            column_mapping = {
                                "title": "vulnerability",
                                "bulletin_id": "oem_name",
                                "severity": "severity_level",
                                "cve_identifier(s)": "unique_id",
                                "publish_date": "published_date",
                                "last_updated": "last_updated",
                                "url": "url"
                            }
                            df_nvidia = df.rename(columns=column_mapping)
                            result_df = query_nvidia_bot(query, df_nvidia)
                        elif selected_oem == "Palo Alto Networks":
                            result_df = query_palo_alto_bot(query, df)
                        elif selected_oem == "Cisco":
                            # Align Cisco data with expected column names for query_cisco_bot
                            column_mapping = {
                                "description": "severity"  # Adjust based on actual data
                            }
                            df_cisco = df.rename(columns=column_mapping)
                            result_df = query_cisco_bot(query, df_cisco)
                        else:
                            response = "Chatbot queries are currently supported only for NVIDIA, Palo Alto Networks, and Cisco. Please select one of these OEMs."
                            result_df = None

                        # Handle chatbot response
                        if result_df is not None:
                            if "Response" in result_df.columns and "❓" in result_df["Response"].iloc[0]:
                                response = result_df["Response"].iloc[0]
                                result_df = None
                            else:
                                response = f"Found {len(result_df)} results for your query."
                        st.session_state.chat_history.append(("You", query))
                        st.session_state.chat_history.append(("AI", (response, result_df)))
                except Exception as e:
                    st.error(f"❌ Failed to process query: {str(e)}")
                    logging.error(f"Chatbot query failed: {str(e)}")
                    logging.error(traceback.format_exc())

            try:
                for role, msg in st.session_state.chat_history:
                    with st.chat_message("assistant" if role == "AI" else "user"):
                        if role == "You":
                            st.markdown(msg)
                        else:
                            message, df_result = msg
                            st.markdown(message)
                            if df_result is not None and isinstance(df_result, pd.DataFrame):
                                # Ensure date columns are strings before rendering
                                for date_col in ["published_date", "last_updated", "publish_date"]:
                                    if date_col in df_result.columns:
                                        df_result[date_col] = df_result[date_col].astype(str).replace("nan", "N/A").replace("", "N/A")
                                # Select and rename columns for display, making 'url' clickable
                                display_df = df_result.rename(columns={
                                    "product_name": "Product",
                                    "oem_name": "OEM",
                                    "severity_level": "Severity",
                                    "severity": "Severity",
                                    "unique_id": "CVE ID",
                                    "cve_identifier(s)": "CVE ID",
                                    "published_date": "Published",
                                    "publish_date": "Published",
                                    "vulnerability": "Vulnerability",
                                    "title": "Vulnerability",
                                    "description": "Description",
                                    "url": "Link",
                                    "bulletin_id": "Bulletin ID",
                                    "product_version": "Version",
                                    "affected_versions": "Affected Versions",
                                    "unaffected_versions": "Unaffected Versions",
                                    "last_updated": "Last Updated"
                                })
                                # Reorder columns for better readability, excluding any not in the display
                                display_columns = ["Product", "Version", "OEM", "Bulletin ID", "Severity", "CVE ID", "Vulnerability", "Description", "Published", "Last Updated", "Affected Versions", "Unaffected Versions", "Link"]
                                display_df = display_df[[col for col in display_columns if col in display_df.columns]]
                                # Convert 'Link' column to clickable HTML links
                                if "Link" in display_df.columns:
                                    display_df["Link"] = display_df["Link"].apply(lambda x: f'<a href="{x}" target="_blank">View Details</a>' if pd.notnull(x) and x.strip() else "N/A")
                                # Display the DataFrame as an HTML table with clickable links
                                html = display_df.to_html(escape=False, index=False, classes="vuln-table")
                                st.markdown(html, unsafe_allow_html=True)
            except Exception as e:
                st.error(f"❌ Error rendering chat history: {str(e)}")
                logging.error(f"Error rendering chat history: {str(e)}")

            if st.button("Clear Chat"):
                st.session_state.chat_history.clear()
                st.rerun()
            st.markdown('</div>', unsafe_allow_html=True)

# Auth Restriction
if page == "Dashboard" and not is_authenticated():
    st.error("❌ Please login to access this page.")

# Login Page
elif page == "Login":
    if not is_authenticated():
        st.markdown("## 🔐 Login to Your Tracker")
        st.markdown("#### Enter your credentials to continue")
        username = st.text_input("👤 Username")
        password = st.text_input("🔐 Password", type="password")

        if st.button("Login", use_container_width=True):
            if username and password:
                try:
                    user_data = login(username, password)
                    if user_data is not None:  # Check if login was successful
                        st.success("✅ Login successful!")
                        st.session_state["authenticated"] = True
                        st.session_state["username"] = username
                        st.session_state["user_email"] = user_data.get("email", username)  # Use email from login response
                        st.session_state["token"] = user_data.get("token")  # Store the token
                        st.rerun()
                    else:
                        st.error("❌ Invalid credentials")
                except requests.RequestException as e:
                    logging.error(f"Login error: {e}")
                    st.error(f"❌ Network error: {e}")
            else:
                st.error("❌ Please enter both fields")
    else:
        st.sidebar.button("🚪 Logout", on_click=logout)
        st.success(f"✅ Logged in as {st.session_state.get('username', 'user')}")

# Signup Page
elif page == "Signup":
    st.markdown("## 📝 Create Your Account")
    st.markdown("#### Start monitoring vulnerabilities seamlessly")
    new_username = st.text_input("👤 Username")
    new_email = st.text_input("📧 Email")
    new_password = st.text_input("🔐 Password", type="password")

    if st.button("Register", use_container_width=True):
        if new_username and new_email and new_password:
            if not is_valid_email(new_email):
                st.error("❌ Please enter a valid email address (e.g., user@example.com).")
            else:
                try:
                    if signup(new_username, new_email, new_password):
                        st.success("✅ Account created! Please login.")
                        st.balloons()
                    else:
                        st.error("❌ Username or email already exists.")
                except requests.RequestException as e:
                    logging.error(f"Signup error: {e}")
                    st.error(f"❌ Network error: {e}")
        else:
            st.warning("⚠️ Please fill in all fields.")