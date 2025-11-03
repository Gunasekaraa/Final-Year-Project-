import requests
from bs4 import BeautifulSoup
import pandas as pd
from schedule import every, repeat, run_pending
import time
from scraper_app.modules.report import send_vulnerability_report
from scraper_app.modules.processing import ai_filter_critical_high_vulnerabilities

OEM_WEBSITES = [
    {"name": "Cisco", "url": "https://sec.cloudapps.cisco.com/security/center/publicationListing.x"},
    {"name": "Intel", "url": "https://www.intel.com/content/www/us/en/security-center/default.html"},
]

PREDEFINED_EMAILS = ["stakeholder1@example.com", "stakeholder2@example.com"]
seen_vulnerabilities = set()

def scrape_vulnerabilities(oem_name, url):
    # Use the updated scraper.py function (already updated above)
    if "cisco.com" in url:
        return scrape_cisco(url)
    elif "intel.com" in url:
        return scrape_intel(url)
    else:
        print(f"Unsupported URL: {url}")
        return pd.DataFrame()

@repeat(every().hour)
def monitor_vulnerabilities():
    print("Checking for new vulnerabilities...")
    for oem in OEM_WEBSITES:
        df = scrape_vulnerabilities(oem["name"], oem["url"])
        if not df.empty:
            # Use AI to filter for Critical/High severity
            print("Filtering vulnerabilities with AI...")
            filtered_df = ai_filter_critical_high_vulnerabilities(df)
            if not filtered_df.empty:
                print(f"Found {len(filtered_df)} new critical/high vulnerabilities for {oem['name']}")
                # Add unique IDs to seen_vulnerabilities
                for unique_id in filtered_df["Unique ID"]:
                    seen_vulnerabilities.add(unique_id)
                # Send email to predefined email addresses
                success, message = send_vulnerability_report(
                    PREDEFINED_EMAILS, filtered_df,
                    email_sender="arunsic63@gmail.com",
                    email_password="stqg wcqr ipdr qlcc"
                )
                if success:
                    print(f"Email sent to {PREDEFINED_EMAILS}: {message}")
                else:
                    print(f"Failed to send email: {message}")

if __name__ == "__main__":
    print("Starting vulnerability monitoring...")
    while True:
        run_pending()
        time.sleep(60)