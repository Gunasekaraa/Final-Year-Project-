import pandas as pd
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
import logging
import time
from .utils import setup_driver, fetch_nvd_data
import shutil

def scrape_cisco(url):
    """Scrape Cisco security advisories using Selenium."""
    driver, temp_dir = setup_driver()
    # Add a user-agent to mimic a real browser
    driver.execute_cdp_cmd("Network.setUserAgentOverride", {
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    })
    data = []
    try:
        logging.info(f"Navigating to Cisco URL: {url}")
        driver.get(url)
        # Wait until at least one advisory row is loaded
        logging.info("Waiting for Cisco advisory rows to load...")
        try:
            WebDriverWait(driver, 120).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "tr.rowRepeat"))
            )
        except TimeoutException as e:
            logging.error(f"Timeout waiting for advisory rows: {e}")
            # Save page source for debugging
            with open("../../cisco_error.html", "w", encoding="utf-8") as f:
                f.write(driver.page_source)
            raise
        
        # Save main page HTML for debugging
        with open("../../cisco_main.html", "w", encoding="utf-8") as f:
            f.write(driver.page_source)
        
        # Locate all advisory rows
        rows = driver.find_elements(By.CSS_SELECTOR, "tr.rowRepeat")
        logging.info(f"Found {len(rows)} rows in Cisco table")
        if not rows:
            logging.warning("No rows found with selector 'tr.rowRepeat'. Check site structure.")
            # Save page source for debugging
            with open("../../cisco_no_rows.html", "w", encoding="utf-8") as f:
                f.write(driver.page_source)
            return pd.DataFrame()
        
        for row in rows:
            try:
                advisory_elem = row.find_element(By.CSS_SELECTOR, "span.advListItem a")
                advisory_title = advisory_elem.text.strip()
                href = advisory_elem.get_attribute("href") if advisory_elem else "#"
            except Exception:
                advisory_title, href = "N/A", "#"
            
            try:
                impact_elem = row.find_element(By.CSS_SELECTOR, "td.impactTD")
                impact = impact_elem.text.strip()
            except Exception:
                impact = "N/A"
            
            try:
                cve_elem = row.find_element(By.CSS_SELECTOR, "td:nth-child(3)")
                cve_text = cve_elem.text.strip()
            except Exception:
                cve_text = "N/A"
            
            try:
                last_updated_elem = row.find_element(By.CSS_SELECTOR, "td:nth-child(4) span.ng-binding")
                last_updated = last_updated_elem.text.strip()
                if not last_updated:  # Fallback if text is empty
                    last_updated = driver.execute_script("return arguments[0].innerText;", last_updated_elem).strip()
                logging.debug(f"Extracted last_updated: {last_updated}")
            except Exception:
                last_updated = "N/A"
                logging.warning("Failed to extract last_updated for a row")
            
            try:
                version_elem = row.find_element(By.CSS_SELECTOR, "td:nth-child(5)")
                version = version_elem.text.strip()
            except Exception:
                version = "N/A"
            
            # Fetch NVD data using the first CVE if multiple are present
            cve_ids = [cve.strip() for cve in cve_text.split() if cve.strip().startswith("CVE-")]
            cve_id = cve_ids[0] if cve_ids else "N/A"
            nvd = fetch_nvd_data(cve_id) if cve_id != "N/A" else {
                "CVSS Score": "N/A",
                "Severity Level": "N/A",
                "Mitigation Strategy": "N/A"
            }
            severity = nvd["Severity Level"].capitalize() if nvd["Severity Level"] != "N/A" else "N/A"
            
            data.append({
                "OEM Name": "Cisco",
                "Vulnerability": advisory_title,
                "Description": impact,
                "URL": href,
                "Last Updated": last_updated,
            })
            time.sleep(0.6)
        
        df = pd.DataFrame(data)
        if df.empty:
            logging.warning("No vulnerabilities found for Cisco.")
        else:
            logging.info(f"Scraped Cisco DataFrame:\n{df.head().to_string()}")
        return df
        
    except (TimeoutException, WebDriverException) as e:
        logging.error(f"Error scraping Cisco: {e}")
        # Save page source for debugging
        with open("../../cisco_error.html", "w", encoding="utf-8") as f:
            f.write(driver.page_source)
        return pd.DataFrame()
    finally:
        driver.quit()
        shutil.rmtree(temp_dir, ignore_errors=True)