import pandas as pd
import time
import logging
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.support.ui import Select
from selenium.webdriver.common.by import By
from bs4 import BeautifulSoup
from .utils import fetch_nvd_data

def scrape_dell(url):
    """Scrape Dell security advisories using Selenium and BeautifulSoup with a cap of 100 entries."""
    logging.info("▶️ scrape_dell() has been entered")
    print("▶️ scrape_dell() hit")  # Useful for Streamlit console

    # Setup headless browser
    options = webdriver.ChromeOptions()
    options.add_argument('--headless')  # Remove for debugging
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)

    data = []

    try:
        # Open the target URL
        logging.info(f"Navigating to Dell URL: {url}")
        driver.get(url)

        # Wait for the page to load
        time.sleep(5)

        # Set items per page to 100
        logging.info("Setting items per page to 100")
        select_element = driver.find_element(By.ID, "409505145-per-page")
        select = Select(select_element)
        select.select_by_value("100")

        # Wait for page reload
        time.sleep(5)

        # Parse page source with BeautifulSoup
        logging.info("Parsing page source with BeautifulSoup")
        soup = BeautifulSoup(driver.page_source, "html.parser")

        # Extract advisories
        rows = soup.find_all("div", class_="dds__tr", role="row")
        logging.info(f"Found {len(rows)} rows in Dell table")

        if not rows:
            logging.warning("No rows found with selector 'div.dds__tr[role='row']'. Check site structure.")
            with open("dell_no_rows.html", "w", encoding="utf-8") as f:
                f.write(driver.page_source)
            return pd.DataFrame()

        for idx, row in enumerate(rows[:100]):
            cells = row.find_all("div", class_="dds__td")
            if len(cells) < 6:
                logging.warning(f"Skipping row {idx + 1}: Insufficient columns ({len(cells)})")
                continue

            # Extract Impact
            impact = cells[0].find("span", class_="dds__badge__label")
            impact_text = impact.text.strip() if impact else "N/A"

            # Extract Title and URL
            title = cells[1].find("a", class_="dds__link")
            title_text = title.text.strip() if title else "Unknown"
            full_url = title["href"] if title else "#"
            if full_url.startswith("/"):
                full_url = f"https://www.dell.com{full_url}"

            # Extract Type (not used in output but logged for debugging)
            type_span = cells[2].find("span", class_="dds__table__cell")
            type_text = type_span.text.strip() if type_span else "Advisory"

            # Extract CVE Identifier
            cve_span = cells[3].find("span", class_="dds__table__cell dds__ellipses")
            cve_text = cve_span.text.strip() if cve_span else "N/A"

            # Extract Published and Updated dates
            published_div = cells[4].find("div", attrs={"name": True})
            updated_div = cells[5].find("div", attrs={"name": True})
            published_text = published_div.text.strip() if published_div else "N/A"
            updated_text = updated_div.text.strip() if updated_div else "N/A"

            # Fetch NVD data using the first CVE if multiple are present
            cve_ids = [cve.strip() for cve in cve_text.split(",") if cve.strip().startswith("CVE-")]
            cve_id = cve_ids[0] if cve_ids else "N/A"
            nvd = fetch_nvd_data(cve_id) if cve_id != "N/A" else {
                "CVSS Score": "N/A",
                "Severity Level": "N/A",
                "Mitigation Strategy": "N/A"
            }
            severity = nvd["Severity Level"].capitalize() if nvd["Severity Level"] != "N/A" else impact_text

            logging.debug(f"Extracted row {idx + 1} - Title: {title_text}, CVE: {cve_text}, Updated: {updated_text}, Published: {published_text}, URL: {full_url}")

            data.append({
                "OEM Name": "Dell",
                "Vulnerability": title_text,
                "Description": severity,
                "Published Date": published_text,
                "Unique ID": cve_id,
                "URL": full_url,
                "Last Updated": updated_text
            })

        df = pd.DataFrame(data)
        if df.empty:
            logging.warning("No vulnerabilities found for Dell.")
        else:
            logging.info(f"Scraped Dell DataFrame:\n{df.head().to_string()}")
        return df

    except Exception as e:
        logging.error(f"Dell scraper error: {e}", exc_info=True)
        with open("dell_error.html", "w", encoding="utf-8") as f:
            f.write(driver.page_source)
        return pd.DataFrame()

    finally:
        driver.quit()