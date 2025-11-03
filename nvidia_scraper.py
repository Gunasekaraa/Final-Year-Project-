import pandas as pd
import time
import logging
import shutil
import re
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException, StaleElementReferenceException
from webdriver_manager.chrome import ChromeDriverManager
from .utils import setup_driver

def scrape_nvidia(url):
    """Scrape NVIDIA security advisories using optimized Selenium + BeautifulSoup."""
    logging.info("▶️ scrape_nvidia() has been entered")
    print("▶️ scrape_nvidia() hit")  # Useful for Streamlit console

    driver, temp_dir = setup_driver()
    data = []

    try:
        driver.get(url)

        # ✅ Wait for body to load
        WebDriverWait(driver, 20).until(
            EC.presence_of_element_located((By.TAG_NAME, "body"))
        )

        # ✅ Wait for table to load
        WebDriverWait(driver, 30).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "table.compare-table"))
        )
        logging.info("✅ Table loaded successfully")

        # ✅ Handle dynamic content with retry logic
        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                table = driver.find_element(By.CSS_SELECTOR, "table.compare-table")
                rows = table.find_elements(By.TAG_NAME, "tr")[1:]  # Skip header
                logging.info(f"🔍 Found {len(rows)} NVIDIA rows on attempt {attempt + 1}")

                for index, row in enumerate(rows, start=1):
                    try:
                        cols = row.find_elements(By.TAG_NAME, "td")
                        if len(cols) >= 6:
                            title_link = cols[0].find_element(By.TAG_NAME, "a")
                            severity_td = cols[2]
                            # Extract severity
                            severity_data = severity_td.get_attribute("data")
                            severity_text = severity_td.text.strip()
                            severity = severity_data if severity_data else severity_text
                            # Validate severity
                            valid_severities = {"N/A", "None", "NVIDIA products are not affected", "Low", "Medium", "High", "Critical"}
                            if severity not in valid_severities:
                                logging.warning(f"Unexpected severity '{severity}' for row {index}, using 'N/A'")
                                severity = "N/A"
                            elif severity in {"N/A", "None"}:
                                logging.info(f"Row {index} has no severity, using '{severity}'")

                            # Clean the Publish Date
                            publish_date = cols[4].text.strip()
                            publish_date = re.sub(r'<.*?>', '', publish_date)  # Remove HTML tags
                            publish_date = re.split(r' - | \(', publish_date)[0]  # Remove extra text like " - Updated" or "(Details)"
                            publish_date = publish_date.strip()

                            data.append({
                                "Title": title_link.text.strip(),
                                "Bulletin ID": cols[1].text.strip(),
                                "Severity": severity,
                                "CVE Identifier(s)": cols[3].text.strip().replace('\n', ' '),
                                "Publish Date": publish_date,
                                "Last Updated": cols[5].text.strip(),
                                "URL": title_link.get_attribute("href")
                            })
                    except StaleElementReferenceException:
                        logging.warning(f"Stale element detected at row {index}, re-fetching rows...")
                        time.sleep(2)
                        break
                else:
                    break
            except StaleElementReferenceException:
                logging.warning(f"Stale element on attempt {attempt + 1}, retrying...")
                time.sleep(2)
                continue
        else:
            logging.error("Max retry attempts reached, some data may be missing")

        return pd.DataFrame(data)

    except (TimeoutException, WebDriverException) as e:
        logging.error(f"NVIDIA scraper error: {e}", exc_info=True)
        return pd.DataFrame()

    finally:
        driver.quit()
        shutil.rmtree(temp_dir, ignore_errors=True)