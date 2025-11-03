import pandas as pd
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from bs4 import BeautifulSoup
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

# Set up Selenium with Chrome options (aligned with standalone and NVIDIA script)
chrome_options = Options()
chrome_options.add_argument("--headless")
chrome_options.add_argument("--no-sandbox")
chrome_options.add_argument("--disable-dev-shm-usage")
chrome_options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
chrome_options.add_argument("--disable-blink-features=AutomationControlled")
chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
chrome_options.add_experimental_option("useAutomationExtension", False)
chrome_options.add_argument("--window-size=1920,1080")
chrome_options.add_argument("--disable-extensions")
chrome_options.add_argument("--start-maximized")
chrome_options.add_argument("--disable-gpu")
chrome_options.add_argument("--ignore-certificate-errors")

def scrape_palo_alto(url="https://security.paloaltonetworks.com/"):
    driver = None
    data = []
    
    try:
        # Initialize driver with ChromeDriverManager (consistent with NVIDIA script)
        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)
        driver.get(url)
        print(f"Navigating to Palo Alto URL: {url}")

        # Wait for the table with explicit wait
        try:
            table = WebDriverWait(driver, 60).until(
                EC.presence_of_element_located((By.CLASS_NAME, "tbl.salist.wide"))
            )
            print("Table with class 'tbl salist wide' found")
        except:
            print("WebDriverWait failed to find table. Falling back to time.sleep")
            time.sleep(30)
            table = driver.find_elements(By.CLASS_NAME, "tbl.salist.wide")
            table = table[0] if table else None
            if not table:
                print("Table still not found after fallback")
                raise Exception("Table not found")

        # Scroll to table for visibility
        driver.execute_script("arguments[0].scrollIntoView();", table)
        time.sleep(5)

        # Wait for rows
        try:
            WebDriverWait(driver, 60).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "table.tbl.salist.wide tbody tr"))
            )
            print("At least one row found in table body")
        except:
            print("WebDriverWait failed to find rows. Falling back to time.sleep")
            time.sleep(30)
            if not driver.find_elements(By.CSS_SELECTOR, "table.tbl.salist.wide tbody tr"):
                print("Rows still not found after fallback")
                raise Exception("Rows not found")

        # Handle "Load More" button
        max_load_attempts = 5
        load_attempt = 0
        while load_attempt < max_load_attempts:
            try:
                load_more_button = driver.find_element(By.XPATH, "//button[contains(text(), 'Load More')]")
                if load_more_button.is_displayed():
                    load_more_button.click()
                    time.sleep(5)
                    print(f"Clicked 'Load More' button (attempt {load_attempt + 1})")
                    load_attempt += 1
                else:
                    print("No 'Load More' button visible")
                    break
            except:
                print("No more 'Load More' buttons or error occurred")
                break

        # Debugging outputs
        driver.save_screenshot("paloalto_screenshot_app.png")
        print("Screenshot saved to paloalto_screenshot_app.png")
        
        console_logs = driver.get_log("browser")
        with open("paloalto_console_logs_app.txt", "w", encoding="utf-8") as f:
            for log in console_logs:
                f.write(f"{log['level']}: {log['message']}\n")
        print("Browser console logs saved to paloalto_console_logs_app.txt")

        # Parse page source
        soup = BeautifulSoup(driver.page_source, "html.parser")
        with open("paloalto_page_source_app.html", "w", encoding="utf-8") as f:
            f.write(soup.prettify())
        print("Page source saved to paloalto_page_source_app.html")

        # Extract table
        table = soup.find("table", class_="tbl salist wide")
        if not table:
            print("Could not find table in page source")
            raise Exception("Table not found in page source")

        tbodies = table.find_all("tbody")
        if not tbodies:
            print("No <tbody> tags found")
            raise Exception("No tbody tags found")

        rows = []
        for tbody in tbodies:
            tbody_rows = tbody.find_all("tr")
            rows.extend(tbody_rows)
            print(f"Found {len(tbody_rows)} rows in a <tbody>")

        if not rows:
            print("No rows found in any <tbody>")
            raise Exception("No rows found")

        print(f"Total rows found: {len(rows)}")

        # Process rows
        for row in rows:
            cols = row.find_all("td")
            if len(cols) != 7:
                continue

            cvss_score = cols[0].text.strip()
            summary_cell = cols[1].find("a")
            summary = summary_cell.text.strip() if summary_cell else "N/A"
            url = summary_cell["href"] if summary_cell else "N/A"
            url = f"https://security.paloaltonetworks.com{url}" if url != "N/A" and not url.startswith("http") else url
            cve_id = summary.split()[0] if summary.startswith("CVE-") or summary.startswith("PAN-SA-") else "N/A"
            versions = [div.text.strip() for div in cols[2].find_all("div") if div.text.strip()]
            product_name = versions[0] if versions else "Unknown"
            affected = [div.text.strip() for div in cols[3].find_all("div") if div.text.strip()]
            unaffected = [div.text.strip() for div in cols[4].find_all("div") if div.text.strip()]
            published_date = cols[5].text.strip()
            updated_date = cols[6].text.strip()

            severity = "N/A"
            try:
                if cvss_score.lower() == "i":
                    severity = "Informational"
                else:
                    score = float(cvss_score)
                    if score >= 9.0:
                        severity = "Critical"
                    elif score >= 7.0:
                        severity = "High"
                    elif score >= 4.0:
                        severity = "Medium"
                    else:
                        severity = "Low"
            except ValueError:
                pass

            data.append({
                "Product Name": product_name,
                "Product Version": ", ".join(versions[1:]) if len(versions) > 1 else "N/A",
                "OEM Name": "Palo Alto Networks",
                "Vulnerability": summary,
                "Description": cve_id,
                "Published Date": published_date,
                "Last Updated": updated_date,
                "Unique ID": cve_id,
                "URL": url,
                "Severity Level": severity,
                "Affected Versions": "; ".join(affected),
                "Unaffected Versions": "; ".join(unaffected)
            })

        # Create DataFrame
        df = pd.DataFrame(data)
        if not df.empty:
            df = df.sort_values(by="Unique ID").drop_duplicates(subset=["Unique ID"], keep="first")
            df["Published Date"] = pd.to_datetime(df["Published Date"], errors='coerce')
            df = df.sort_values(by="Published Date", ascending=False).reset_index(drop=True)
            print("Scraped Palo Alto DataFrame:")
            print(df.head().to_string())
            df.to_csv("paloalto_vulnerabilities.csv", index=False)
            print("Data saved to paloalto_vulnerabilities.csv")
        else:
            print("No data scraped")

        return df

    except Exception as e:
        print(f"Error in Palo Alto scraper: {e}")
        return pd.DataFrame(data)

    finally:
        if driver:
            driver.quit()

if __name__ == "__main__":
    scrape_palo_alto()