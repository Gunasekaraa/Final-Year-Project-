import time
import pandas as pd
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import WebDriverException
import requests
import os
from dotenv import load_dotenv
import logging
import tempfile
import shutil
from webdriver_manager.chrome import ChromeDriverManager

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', filename="../../app.log")

# Load .env
load_dotenv()
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

def setup_driver():
    """Set up ChromeDriver with a unique user data directory."""
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--window-size=1920x1080")
    
    # Create a temporary directory for user data
    temp_dir = tempfile.mkdtemp()
    options.add_argument(f"--user-data-dir={temp_dir}")
    
    try:
        # Use webdriver-manager to automatically download the correct ChromeDriver version
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)
        logging.info(f"ChromeDriver initialized with user-data-dir: {temp_dir}")
        return driver, temp_dir
    except WebDriverException as e:
        logging.error(f"ChromeDriver initialization failed: {e}")
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise

def cleanup_driver(driver, temp_dir):
    """Clean up the WebDriver and temporary directory."""
    try:
        driver.quit()
    except:
        pass
    try:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
            logging.info(f"Temporary directory {temp_dir} cleaned up.")
    except:
        logging.warning(f"Failed to clean up temporary directory {temp_dir}.")

def fetch_nvd_data(cve_id):
    """Fetch CVSS score, severity, and mitigation from NVD API."""
    if not NVD_API_KEY:
        logging.warning("NVD_API_KEY not set, returning default values.")
        return {"CVSS Score": "N/A", "Severity Level": "N/A", "Mitigation Strategy": "N/A"}
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {"apiKey": NVD_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        if "vulnerabilities" in data and data["vulnerabilities"]:
            cve = data["vulnerabilities"][0]["cve"]
            score = cve["metrics"].get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A")
            severity = cve["metrics"].get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "N/A")
            mitigation = next((desc["value"] for desc in cve["descriptions"] if "mitigation" in desc["value"].lower()), "N/A")
            return {"CVSS Score": score, "Severity Level": severity, "Mitigation Strategy": mitigation}
        else:
            logging.warning(f"No NVD data found for {cve_id}.")
            return {"CVSS Score": "N/A", "Severity Level": "N/A", "Mitigation Strategy": "N/A"}
    except Exception as e:
        logging.error(f"NVD API failed for {cve_id}: {e}")
        return {"CVSS Score": "N/A", "Severity Level": "N/A", "Mitigation Strategy": "N/A"}