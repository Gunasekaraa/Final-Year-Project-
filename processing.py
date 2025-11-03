import pandas as pd
import json
import traceback
import logging
from google.generativeai import GenerativeModel, configure
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.ERROR, filename="app.log", filemode="w")

# Gemini API Configuration
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    raise ValueError("GEMINI_API_KEY not found in .env file. Please add it.")
configure(api_key=GEMINI_API_KEY)

# Define models (based on Gemini API availability, hardcoded for now)
PRIMARY_MODEL = "gemini-1.5-pro-latest"  # Gemini Pro model
FALLBACK_MODEL = "gemini-1.5-flash-latest"  # Lightweight fallback model

def find_impact_column(df):
    """Find a column that likely represents impact/severity."""
    possible_columns = ["Impact", "impact", "Severity", "severity", "RiskLevel"]
    for col in df.columns:
        if col in possible_columns:
            return col
    # If no exact match, look for columns containing "impact" or "severity" in the name
    for col in df.columns:
        if "impact" in col.lower() or "severity" in col.lower() or "risk" in col.lower():
            return col
    return None

def ai_generate_summary(df):
    """
    Generates an AI-powered summary of the vulnerability data using Gemini API.
    """
    try:
        if df.empty:
            return "⚠️ No data available for summarization."

        # Find the impact/severity column
        impact_col = find_impact_column(df)
        if not impact_col:
            logging.error(f"No impact/severity column found in DataFrame. Available columns: {df.columns.tolist()}")
            return "❌ Error: No impact/severity column found in the dataset."

        # Extract key statistics
        # Handle both text and numeric severity values
        def is_critical(value):
            if pd.isna(value):
                return False
            if isinstance(value, str):
                return "critical" in value.lower() or "crit" in value.lower()
            try:
                return float(value) >= 9.0  # CVSS score for critical
            except (ValueError, TypeError):
                return False

        def is_high(value):
            if pd.isna(value):
                return False
            if isinstance(value, str):
                return "high" in value.lower()
            try:
                score = float(value)
                return 7.0 <= score < 9.0  # CVSS score for high
            except (ValueError, TypeError):
                return False

        critical_count = df[impact_col].apply(is_critical).sum()
        high_count = df[impact_col].apply(is_high).sum()
        total = df.shape[0]
        mitigation_available = df["Mitigation"].notna().sum() if "Mitigation" in df.columns else 0

        # Construct summary prompt
        prompt = f"""
        Total Vulnerabilities: {total}
        Critical Impact: {critical_count}
        High Impact: {high_count}
        Mitigation Strategies Available: {mitigation_available}

        Provide a brief, professional analysis highlighting trends and key takeaways.
        """

        # Gemini chat completion request
        try:
            model = GenerativeModel(PRIMARY_MODEL)
            response = model.generate_content(prompt)
            return response.text
        except Exception as primary_error:
            logging.warning(f"Primary model failed: {str(primary_error)}. Falling back to {FALLBACK_MODEL}.")
            model = GenerativeModel(FALLBACK_MODEL)
            response = model.generate_content(prompt)
            return response.text

    except Exception as e:
        logging.error(traceback.format_exc())
        return f"❌ Error generating AI summary: {str(e)}"

def query_dataframe(df, query):
    """Uses Gemini API to process user queries on the dataframe."""
    try:
        if df.empty:
            return "⚠️ The provided vulnerability dataset is empty."

        # Convert timestamps to strings
        df_copy = df.copy()
        for col in df_copy.columns:
            if pd.api.types.is_datetime64_any_dtype(df_copy[col]):
                df_copy[col] = df_copy[col].dt.strftime('%Y-%m-%d %H:%M:%S')

        # Find the impact/severity column
        impact_col = find_impact_column(df_copy)
        if not impact_col:
            logging.error(f"No impact/severity column found in DataFrame. Available columns: {df_copy.columns.tolist()}")
            return "❌ Error: No impact/severity column found in the dataset."

        # Debug: Log the unique values in the impact column
        logging.info(f"Unique values in '{impact_col}' column: {df_copy[impact_col].unique()}")
        logging.info(f"Total rows in DataFrame: {len(df_copy)}")

        # Preprocess query and filter data first
        query_lower = query.lower()
        warning = ""
        if "critical" in query_lower:
            # Normalize impact column
            df_copy[impact_col] = df_copy[impact_col].str.strip().str.lower()
            # Filter for critical vulnerabilities (more flexible matching)
            df_subset = df_copy[df_copy[impact_col].str.contains("critical|crit", case=False, na=False)]
            logging.info(f"Number of rows with 'Critical' impact: {len(df_subset)}")
            if df_subset.empty:
                return "No critical vulnerabilities found in the data."
        elif "high" in query_lower:
            # Normalize impact column
            df_copy[impact_col] = df_copy[impact_col].str.strip().str.lower()
            # Filter for high impact vulnerabilities
            df_subset = df_copy[df_copy[impact_col].str.contains("high", case=False, na=False)]
            logging.info(f"Number of rows with 'High' impact: {len(df_subset)}")
            if df_subset.empty:
                return "No high impact vulnerabilities found in the data."
        else:
            # For other queries, use the full dataset (will limit later if needed)
            df_subset = df_copy

        # Now limit to a manageable subset if necessary
        if len(df_subset) > 10:
            df_subset = df_subset.head(10)  # Limit to 10 rows after filtering
            warning = "⚠️ Results limited to first 10 matching rows due to size constraints."
        else:
            warning = ""

        # Select relevant columns to reduce token usage
        # Adjust columns based on whether it's Cisco or Intel data
        if "cisco" in df.get("Unique ID", [""])[0].lower():
            relevant_columns = ["Product Version", "Advisory", "impact", "Published Date", "Unique ID"]
        else:  # Intel
            relevant_columns = ["Product Version", "Advisory", "Description", "Severity", "Published Date", "Unique ID"]

        available_columns = [col for col in relevant_columns if col in df_subset.columns]
        if available_columns:
            df_subset = df_subset[available_columns]
        else:
            logging.warning(f"No relevant columns found in DataFrame. Using all columns. Available columns: {df_subset.columns.tolist()}")

        data_json = json.dumps(df_subset.to_dict(orient="records"), ensure_ascii=False)
        if len(data_json) > 4000:  # Arbitrary token limit, adjust based on Gemini API docs
            return "⚠️ Data too large to process. Please reduce the dataset size."

        prompt = f"""
        Vulnerability data schema: {df_subset.columns.tolist()}
        Sample data (JSON, limited to {len(df_subset)} rows): {data_json}
        Query: "{query}"
        Answer using only the provided data. If unanswerable, say so.
        {warning}
        """

        # Gemini chat completion request
        try:
            model = GenerativeModel(PRIMARY_MODEL)
            response = model.generate_content(prompt)
            return response.text
        except Exception as e:
            logging.warning(f"Primary model ({PRIMARY_MODEL}) failed: {str(e)}. Using fallback.")
            model = GenerativeModel(FALLBACK_MODEL)
            response = model.generate_content(prompt)
            return response.text

    except Exception as e:
        logging.error(f"Query processing failed: {traceback.format_exc()}")
        return f"❌ Error processing query: {str(e)}"