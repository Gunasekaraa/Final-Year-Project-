import pandas as pd
import re
import logging

def clean_text(text):
    """Clean and normalize text for consistent processing."""
    return str(text).lower().strip()

def query_palo_alto_bot(question: str, df: pd.DataFrame) -> pd.DataFrame:
    """
    Process a user query and return relevant data from the Palo Alto DataFrame.
    
    Args:
        question (str): The user's query.
        df (pd.DataFrame): The Palo Alto data with specified columns.
    
    Returns:
        pd.DataFrame: Filtered results or an error message.
    """
    question = clean_text(question)

    # Check for required columns
    required_columns = ["product_name", "vulnerability", "published_date", "severity_level", "unique_id", "affected_versions", "unaffected_versions"]
    missing_columns = [col for col in required_columns if col not in df.columns]
    if missing_columns:
        logging.warning(f"Missing columns in DataFrame: {missing_columns}")
        return pd.DataFrame([{"Response": f"❌ Missing required columns: {', '.join(missing_columns)}."}])

    # Convert published_date to datetime
    df["published_date"] = pd.to_datetime(df["published_date"], errors='coerce')

    # Latest advisories
    if "latest" in question or "recent" in question:
        N = 5
        if "10" in question: N = 10
        elif "5" in question: N = 5
        return df.sort_values(by="published_date", ascending=False).head(N)

    # Severity filter
    severities = ["critical", "high", "medium", "low"]
    for level in severities:
        if f"{level} severity" in question or f"{level} vulnerabilities" in question:
            return df[df["severity_level"].str.lower() == level]

    # Product-specific queries
    product_match = re.search(r'for\s+(.+)', question)
    if product_match:
        product = product_match.group(1).strip()
        return df[df["product_name"].str.contains(product, case=False, na=False)]

    # CVE search
    cve_match = re.search(r'cve-\d{4}-\d{4,7}', question)
    if cve_match:
        cve_id = cve_match.group()
        return df[df["unique_id"].str.contains(cve_id, case=False, na=False)]

    # Date-based queries (e.g., "after 2025")
    if "after" in question:
        year_match = re.search(r'after\s+(\d{4})', question)
        if year_match:
            year = int(year_match.group(1))
            cutoff_date = pd.to_datetime(f"{year}-01-01")
            return df[df["published_date"] > cutoff_date]

    # Affected versions
    if "affected versions for" in question:
        id_match = re.search(r'for\s+([A-Z0-9-]+)', question)
        if id_match:
            advisory_id = id_match.group(1)
            result_df = df[df["unique_id"] == advisory_id]
            if not result_df.empty:
                affected = result_df["affected_versions"].iloc[0]
                return pd.DataFrame([{"Affected Versions": affected}])

    # Unaffected versions
    if "unaffected versions for" in question:
        id_match = re.search(r'for\s+([A-Z0-9-]+)', question)
        if id_match:
            advisory_id = id_match.group(1)
            result_df = df[df["unique_id"] == advisory_id]
            if not result_df.empty:
                unaffected = result_df["unaffected_versions"].iloc[0]
                return pd.DataFrame([{"Unaffected Versions": unaffected}])

    # Default response
    return pd.DataFrame([{"Response": "❓ I couldn't understand the question. Please try rephrasing."}])

# Example usage (for testing purposes)
if __name__ == "__main__":
    # Sample data (replace with actual DataFrame loading)
    data = {
        "product_name": ["Prisma Access Browser", "Cloud NGFW, PAN-OS 11.2"],
        "vulnerability": ["PAN-SA-2025-0008", "CVE-2025-0128"],
        "published_date": ["2025-04-09", "2025-04-09"],
        "severity_level": ["high", "medium"],
        "unique_id": ["PAN-SA-2025-0008", "CVE-2025-0128"],
        "affected_versions": ["< 132.83.3017.1", "< 11.2.3"],
        "unaffected_versions": [">= 134.29.5.178", ">= 11.2.3"]
    }
    df = pd.DataFrame(data)
    
    # Test queries
    queries = [
        "latest 5 advisories",
        "critical severity vulnerabilities",
        "vulnerabilities for Prisma Access Browser",
        "details for CVE-2025-0128",
        "affected versions for PAN-SA-2025-0008"
    ]
    for q in queries:
        result = query_palo_alto_bot(q, df)
        print(f"Query: {q}")
        print(result)
        print()