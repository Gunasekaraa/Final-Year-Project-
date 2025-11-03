import pandas as pd
import re
import logging

def clean_text(text):
    """Clean and normalize text for consistent processing."""
    return str(text).lower().strip()

def query_nvidia_bot(question: str, df: pd.DataFrame) -> pd.DataFrame:
    """
    Process a user query and return relevant data from the NVIDIA DataFrame.
    
    Args:
        question (str): The user's query.
        df (pd.DataFrame): The NVIDIA data with specified columns.
    
    Returns:
        pd.DataFrame: Filtered results or an error message.
    """
    question = clean_text(question)

    # Check for required columns
    required_columns = ["title", "bulletin_id", "severity", "cve_identifier(s)", "publish_date", "last_updated", "url", "severity_level"]
    missing_columns = [col for col in required_columns if col not in df.columns]
    if missing_columns:
        logging.warning(f"Missing columns in DataFrame: {missing_columns}")
        return pd.DataFrame([{"Response": f"❌ Missing required columns: {', '.join(missing_columns)}. Please ensure the data includes these columns."}])

    # Latest advisories
    if "latest" in question or "recent" in question:
        N = 5  # Default to top 5
        if "10" in question: N = 10
        elif "5" in question: N = 5
        return df.sort_values(by="publish_date", ascending=False).head(N)

    # Filter by severity
    severities = ["critical", "high", "medium", "low"]
    for level in severities:
        if f"{level} severity" in question:
            return df[df["severity_level"].str.lower() == level]

    # Show CVEs for a given title
    if "cve for" in question or "cves for" in question:
        for title in df["title"]:
            if pd.isna(title):
                continue
            if clean_text(title) in question:
                return df[df["title"] == title][["title", "cve_identifier(s)"]]

    # Publish date for a given title
    if "publish date for" in question:
        for title in df["title"]:
            if pd.isna(title):
                continue
            if clean_text(title) in question:
                return df[df["title"] == title][["title", "publish_date"]]

    # Last updated for a given title
    if "last updated for" in question:
        for title in df["title"]:
            if pd.isna(title):
                continue
            if clean_text(title) in question:
                return df[df["title"] == title][["title", "last_updated"]]

    # URL by bulletin ID
    if "url for bulletin" in question or "link for bulletin" in question:
        for word in question.split():
            if word.isdigit():
                return df[df["bulletin_id"] == word][["bulletin_id", "url"]]

    # Search title
    if "show details of" in question or "info about" in question:
        keyword = question.replace("show details of", "").replace("info about", "").strip()
        return df[df["title"].str.lower().str.contains(keyword, na=False)]

    # Exact CVE search
    if "search cve" in question or "find cve" in question:
        matches = df[df["cve_identifier(s)"].str.contains("CVE-", case=False, na=False)]
        return matches[matches["cve_identifier(s)"].str.contains(question.split()[-1], case=False, na=False)]

    # Default response for unmatched queries
    return pd.DataFrame([{"Response": "❓ I couldn't understand the question. Please try rephrasing."}])

# Example usage (for testing purposes, uncomment and adjust as needed):
# if __name__ == "__main__":
#     data = {
#         "title": ["NVIDIA® TensorRT LLM - April 2025", "NVIDIA® GPU Display Driver - April 2025", "NVIDIA® NVIDIA App - April 2025", "NVIDIA® NeMo - April 2025"],
#         "bulletin_id": ["5648", "5630", "5644", "5641"],
#         "severity": ["High", "High", "Low", "High"],
#         "cve_identifier(s)": ["CVE-2025-23254", "CVE-2025-23244, CVE-2025-23245, CVE-2025-23246", "CVE-2025-23253", "CVE-2025-23249, CVE-2025-23250, CVE-2025-23251"],
#         "publish_date": ["29 Apr 2025", "24 Apr 2025", "22 Apr 2025", "22 Apr 2025"],
#         "last_updated": ["29 Apr 2025", "24 Apr 2025", "22 Apr 2025", "22 Apr 2025"],
#         "url": ["https://nvidia.custhelp.com/app/answers/detail/a_id/5648", "https://nvidia.custhelp.com/app/answers/detail/a_id/5630", "https://nvidia.custhelp.com/app/answers/detail/a_id/5644", "https://nvidia.custhelp.com/app/answers/detail/a_id/5641"],
#         "severity_level": ["high", "high", "low", "high"]
#     }
#     df = pd.DataFrame(data)
#     result = query_nvidia_bot("latest 5 advisories", df)
#     print(result)