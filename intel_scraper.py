import pandas as pd
import time
import logging
import shutil
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
from bs4 import BeautifulSoup
from .utils import setup_driver, fetch_nvd_data

def scrape_intel(url):
    """Scrape Intel security advisories using Selenium and BeautifulSoup with a cap of 100 entries."""
    logging.info("▶️ scrape_intel() has been entered")
    print("▶️ scrape_intel() hit")  # Useful for Streamlit console

    driver, temp_dir = setup_driver()
    # Add a user-agent to mimic a real browser
    driver.execute_cdp_cmd("Network.setUserAgentOverride", {
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    })
    data = []

    try:
        logging.info(f"Navigating to Intel URL: {url}")
        driver.get(url)

        # Wait for body to load
        WebDriverWait(driver, 20).until(
            EC.presence_of_element_located((By.TAG_NAME, "body"))
        )

        # Try to click the "View all" button
        try:
            view_all = WebDriverWait(driver, 10).until(
                EC.element_to_be_clickable((By.XPATH, '//a[@class="show-more-items intel-ws-ignore"]'))
            )
            driver.execute_script("arguments[0].click();", view_all)
            logging.info("✅ Clicked 'View all' to expand all vulnerabilities.")
            time.sleep(5)  # Wait for all items to load after clicking
        except TimeoutException as e:
            logging.warning(f"⚠️ Could not click 'View all': {e}")

        # Wait for JS and DOM to fully settle
        WebDriverWait(driver, 10).until(
            lambda d: d.execute_script("return document.readyState") == "complete")
        

        # Get the updated page source after loading
        soup = BeautifulSoup(driver.page_source, "html.parser")

        # Extract data from the expanded table
        rows = soup.find_all("tr", class_="data")
        logging.info(f"🔍 Found {len(rows)} Intel advisory rows")

        # If no rows found, save page source for debugging
        if not rows:
            logging.warning("No rows found with selector 'tr.data'. Saving page source for debugging.")
            with open("intel_no_rows.html", "w", encoding="utf-8") as f:
                f.write(driver.page_source)
            return pd.DataFrame()

        # Collect raw info (capped at 100)
        for idx, row in enumerate(rows[:100]):
            columns = row.find_all("td")
            if len(columns) < 4:
                logging.warning(f"Skipping row {idx + 1}: Insufficient columns ({len(columns)})")
                continue

            title = columns[0].text.strip()
            link = columns[0].find("a")["href"] if columns[0].find("a") else "#"
            full_url = f"https://www.intel.com{link}" if link.startswith("/") else link
            cve_text = columns[1].text.strip()  # Assuming this is the CVE or advisory number
            updated = columns[2].text.strip()
            pub_date = columns[3].text.strip()

            # Fetch NVD data using the first CVE if multiple are present
            cve_ids = [cve.strip() for cve in cve_text.split() if cve.strip().startswith("CVE-")]
            cve_id = cve_ids[0] if cve_ids else "N/A"
            nvd = fetch_nvd_data(cve_id) if cve_id != "N/A" else {
                "CVSS Score": "N/A",
                "Severity Level": "N/A",
                "Mitigation Strategy": "N/A"
            }
            severity = nvd["Severity Level"].capitalize() if nvd["Severity Level"] != "N/A" else "N/A"

            logging.debug(f"Extracted row - Title: {title}, CVE: {cve_text}, Updated: {updated}, Published: {pub_date}, URL: {full_url}")

            data.append({
                "OEM Name": "Intel",
                "Vulnerability": title,
                "Published Date": pub_date,
                "URL": full_url,
                "Last Updated": updated
            })

            time.sleep(0.6)  # Small delay to avoid overwhelming the server

        if not data:
            logging.warning("No data extracted from Intel.")
            return pd.DataFrame()

        df = pd.DataFrame(data)
        logging.info(f"Intel scraping completed. Returned {len(df)} rows.")
        return df

    except (TimeoutException, WebDriverException) as e:
        logging.error(f"Intel scraper error: {e}", exc_info=True)
        with open("intel_error.html", "w", encoding="utf-8") as f:
            f.write(driver.page_source)
        return pd.DataFrame()

    finally:
        driver.quit()
        shutil.rmtree(temp_dir, ignore_errors=True)