import pandas as pd
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
import logging

def scrape_adobe(url: str) -> pd.DataFrame:
    """
    Scrape Adobe security bulletins from the specified URL.
    Returns a DataFrame with bulletin details for use in the main project.
    """
    # Set up logging to track progress and errors
    logging.basicConfig(level=logging.INFO)
    logging.info("Starting Adobe scraper")

    # Configure Chrome options
    chrome_options = Options()
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--window-size=1920,1080")
    # Uncomment the line below to run in headless mode; leave commented for debugging
    # chrome_options.add_argument("--headless=new")

    # Use ChromeDriverManager to automatically handle ChromeDriver
    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=chrome_options)

    data = []

    try:
        logging.info(f"Navigating to {url}")
        driver.get(url)

        # Wait for key elements to load (up to 60 seconds)
        logging.info("Waiting for elements to load")
        WebDriverWait(driver, 60).until(
            EC.presence_of_all_elements_located((By.XPATH, "//h2[@id='acrobat'] | //h4"))
        )
        logging.info("Elements loaded successfully")

        # Save page source for debugging
        with open("adobe_page.html", "w", encoding="utf-8") as f:
            f.write(driver.page_source)
        logging.info("Page source saved to adobe_page.html")

        # Extract Adobe Acrobat section
        try:
            acrobat_header = driver.find_element(By.XPATH, "//h2[@id='acrobat']")
            acrobat_table = acrobat_header.find_element(By.XPATH, "following::table[1]")
            rows = acrobat_table.find_elements(By.TAG_NAME, "tr")[1:]  # Skip header
            logging.info(f"Found {len(rows)} rows in Adobe Acrobat table")
            for row in rows:
                cols = row.find_elements(By.TAG_NAME, "td")
                if len(cols) >= 3:
                    data.append({
                        "Section": "Adobe Acrobat",
                        "Title": cols[0].text.strip(),
                        "Posted": cols[1].text.strip(),
                        "Updated": cols[2].text.strip(),
                        "Severity Level": "N/A"
                    })
        except Exception as e:
            logging.error(f"Error extracting Acrobat section: {e}")

        # Extract other sections under h4 headers
        h4_headers = driver.find_elements(By.XPATH, "//h4")
        logging.info(f"Found {len(h4_headers)} h4 headers")
        for header in h4_headers:
            section_name = header.text.strip()
            try:
                table = header.find_element(By.XPATH, "following-sibling::table[1]")
                rows = table.find_elements(By.TAG_NAME, "tr")[1:]  # Skip header
                logging.info(f"Found {len(rows)} rows in section '{section_name}'")
                for row in rows:
                    cols = row.find_elements(By.TAG_NAME, "td")
                    if len(cols) >= 3:
                        data.append({
                            "Section": section_name,
                            "Title": cols[0].text.strip(),
                            "Posted": cols[1].text.strip(),
                            "Updated": cols[2].text.strip(),
                            "Severity Level": "N/A"
                        })
            except Exception as e:
                logging.error(f"Error extracting section '{section_name}': {e}")

    except Exception as e:
        logging.error(f"General error in Adobe scraper: {e}")
    finally:
        driver.quit()

    # Convert the data to a DataFrame
    df = pd.DataFrame(data)
    logging.info(f"Returning DataFrame with {len(df)} rows")
    return df

# Example usage in your main project
if __name__ == "__main__":
    url = "https://helpx.adobe.com/in/security/security-bulletin.html"
    df = scrape_adobe(url)
    print(df)