import pandas as pd
import re
import logging

def clean_text(text):
    """Clean and normalize text for consistent processing."""
    return str(text).lower().strip()

def query_cisco_bot(question: str, df: pd.DataFrame) -> pd.DataFrame:
    """
    Process a user query and return relevant data from the Cisco DataFrame.
    
    Args:
        question (str): The user's query.
        df (pd.DataFrame): The Cisco data with specified columns.
    
    Returns:
        pd.DataFrame: Filtered results or an error message.
    """
    question = clean_text(question)

    # Check for required columns
    required_columns = ["oem_name", "vulnerability", "severity", "url", "last_updated", "severity_level"]
    missing_columns = [col for col in required_columns if col not in df.columns]
    if missing_columns:
        logging.warning(f"Missing columns in DataFrame: {missing_columns}")
        return pd.DataFrame([{"Response": f"❌ Missing required columns: {', '.join(missing_columns)}."}])

    # Convert last_updated to datetime
    df["last_updated"] = pd.to_datetime(df["last_updated"], errors='coerce')

    # Latest advisories
    if "latest" in question or "recent" in question:
        N = 5
        if "10" in question: N = 10
        elif "5" in question: N = 5
        return df.sort_values(by="last_updated", ascending=False).head(N)

    # Severity filter
    severities = ["critical", "high", "medium", "low"]
    for level in severities:
        if f"{level} severity" in question or f"{level} vulnerabilities" in question:
            return df[df["severity_level"].str.lower() == level]

    # Product-specific queries (search within vulnerability title)
    product_match = re.search(r'for\s+(.+)', question)
    if product_match:
        product = product_match.group(1).strip()
        return df[df["vulnerability"].str.contains(product, case=False, na=False)]

    # URL search
    url_match = re.search(r'details for\s+(https?://\S+)', question)
    if url_match:
        url = url_match.group(1)
        return df[df["url"] == url]

    # Date-based queries (e.g., "after 2025")
    if "after" in question:
        year_match = re.search(r'after\s+(\d{4})', question)
        if year_match:
            year = int(year_match.group(1))
            cutoff_date = pd.to_datetime(f"{year}-01-01")
            return df[df["last_updated"] > cutoff_date]

    # Default response
    return pd.DataFrame([{"Response": "❓ I couldn't understand the question. Please try rephrasing."}])

# Example usage (for testing purposes)
if __name__ == "__main__":
    data = {
        "oem_name": ["Cisco"] * 6,
        "vulnerability": [
            "Cisco Catalyst SD-WAN Manager Arbitrary File Overwrite Vulnerability",
            "Multiple Cisco Products Unauthenticated Remote Code Execution in Erlang/OTP SSH Server: April 2025",
            "Cisco IOS XE Wireless Controller Software Arbitrary File Upload Vulnerability",
            "Cisco IOS XE Software for WLC Wireless IPv6 Clients Denial of Service Vulnerability",
            "Cisco IOS XE Software Web-Based Management Interface Command Injection Vulnerability",
            "Cisco IOS, IOS XE, and IOS XR Software TWAMP Denial of Service Vulnerability"
        ],
        "severity": ["Medium", "Critical", "Critical", "High", "High", "High"],
        "url": [
            "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-fileoverwrite-Uc9tXWH",
            "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-erlang-otp-ssh-xyZZy",
            "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wlc-file-uplpd-rHZG9UfC",
            "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wlc-wncd-p6Gvt6HL",
            "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webui-cmdinj-gVn3OKNC",
            "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-twamp-kV4FHugn"
        ],
        "last_updated": [
            "2025-05-08 00:00:00",
            "2025-05-07 00:00:00",
            "2025-05-07 00:00:00",
            "2025-05-07 00:00:00",
            "2025-05-07 00:00:00",
            "2025-05-07 00:00:00"
        ],
        "severity_level": ["medium", "critical", "critical", "high", "high", "high"]
    }
    df = pd.DataFrame(data)
    
    # Test queries
    queries = [
        "latest 5 advisories",
        "critical severity vulnerabilities",
        "vulnerabilities for Cisco IOS XE Software",
        "details for https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-fileoverwrite-Uc9tXWH",
        "advisories after 2024"
    ]
    for q in queries:
        result = query_cisco_bot(q, df)
        print(f"Query: {q}")
        print(result)
        print()