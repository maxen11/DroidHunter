import time
from datetime import datetime
import file_handler as fh
import random
import os
import sys
import subprocess

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options as ChromeOptions

from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

from bs4 import BeautifulSoup
import pandas as pd
import re
import platform
from selenium.common.exceptions import SessionNotCreatedException

# -------------------------
# Detect Chrome/Chromium version (handles Debian "trixie/sid")
# -------------------------
def get_chrome_version():
    candidates = [
        ("google-chrome", ["--version"]),
        ("google-chrome-stable", ["--version"]),
        ("chromium", ["--product-version"]),
        ("chromium-browser", ["--product-version"]),
    ]
    for cmd, args in candidates:
        try:
            output = subprocess.check_output([cmd] + args, stderr=subprocess.STDOUT).decode().strip()
            parts = output.split()
            version = parts[-1] if len(parts) > 1 else parts[0]
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", version):
                return version
        except (FileNotFoundError, subprocess.CalledProcessError):
            continue
    print("Could not detect installed Chrome/Chromium with a valid version number.")
    sys.exit(1)

chrome_version = get_chrome_version()
major_version = chrome_version.split(".")[0]
print(f"Detected Chrome/Chromium version: {chrome_version} (major {major_version})")

# -------------------------
# Configure Chrome WebDriver options
# -------------------------
chrome_options = ChromeOptions()
chrome_options.add_argument("--log-level=3")  # Suppress most browser logs
chrome_options.add_argument("--disable-logging")
chrome_options.add_argument("--disable-usb-keyboard-detect")
chrome_options.add_argument("--disable-usb-discovery")  # Prevents USB scanning logs
chrome_options.add_argument("--disable-device-discovery-notifications")  # Stops USB logging
chrome_options.add_argument("--disable-blink-features=AutomationControlled")  # Reduce bot detection
chrome_options.add_argument("--headless")  # Run without UI
chrome_options.add_argument("--no-sandbox")

# -------------------------
# Use system-installed chromedriver
# -------------------------
chromedriver_path = "/usr/bin/chromedriver"
if not os.path.exists(chromedriver_path):
    print("Error: /usr/bin/chromedriver not found.")
    print("Install it with: sudo apt install chromium-driver")
    sys.exit(1)

service = Service(chromedriver_path, log_output=None)

try:
    driver = webdriver.Chrome(service=service, options=chrome_options)
except SessionNotCreatedException as e:
    if "cannot find Chrome binary" in str(e):
        print("Error: \nGoogle Chrome or Chromium is not installed or not in your PATH.")
        print("Please install it from https://www.google.com/chrome/ or your distro’s package manager.")
        print("Once installed, make sure 'google-chrome' or 'chromium-browser' is accessible from the terminal.")
        exit()
    else:
        raise  # Re-raise if it's a different session error

# -------------------------
# Scraping logic
# -------------------------
BASE_URL = "https://source.android.com"
BULLETIN_URL = "https://source.android.com/docs/security/bulletin"

def get_bulletin_links(start_year=2015, start_month=8, end_year=datetime.today().year, end_month=datetime.today().month):
    links = []
    for year in range(start_year, end_year + 1):
        month_start = start_month if year == start_year else 1
        month_end = end_month if year == end_year else 12
        for month in range(month_start, month_end + 1):
            links.append((f"{BULLETIN_URL}/{year}-{month:02d}-01", year, month))
    return links

def scrape_bulletin(url, year, month):
    if url == "https://source.android.com/docs/security/bulletin/2016-04-01":
        url = "https://source.android.com/docs/security/bulletin/2016-04-02"
    try:
        driver.get(url)
        wait = WebDriverWait(driver, 20)
        wait.until(EC.presence_of_element_located((By.TAG_NAME, "table")))
        wait.until(EC.visibility_of_element_located((By.TAG_NAME, 'h3')))
        wait.until(EC.visibility_of_element_located((By.TAG_NAME, 'span')))
    except:
        print(f"Something went wrong loading... {url}")
        return
    soup = BeautifulSoup(driver.page_source, "html.parser")

    data = {}
    tables = soup.find_all("table")
    h3 = soup.find_all("h3")
    table_categories = [elem.get("data-text") for elem in h3]

    table_index = 0
    for table in tables:
        rows = table.find_all("tr")
        headers = [col.text.strip() for col in rows[0].find_all("th")]
        if "CVE" not in headers:
            continue
        table_title = table_categories[table_index]
        cve_index = headers.index("CVE")

        for row in rows[1:]:
            cols = row.find_all("td")
            if not cols:
                continue
            cve_text = cols[cve_index].text.strip() if len(cols) > cve_index else ""
            match = re.search(r"CVE-\d{4}-\d+", cve_text)
            if not match:
                continue
            cve_id = match.group(0)
            row_data = {header: col.text.strip() for header, col in zip(headers, cols)}
            row_data["Bulletin_URL"] = url
            row_data["Category"] = table_title
            row_data["publishedDate"] = f"{year}-{month:02d}"
            if cve_id in data:
                existing_entry = data[cve_id]
                if not isinstance(existing_entry, list):
                    existing_entry = [existing_entry]
                existing_entry.append(row_data)
                data[cve_id] = existing_entry
            else:
                data[cve_id] = row_data
        table_index += 1

    return data

def collect_asb_data():
    time.sleep(3)
    while True:
        try:
            start_date = input("Start date (yyyy-mm): ")
            if start_date.lower() == "exit": sys.exit()
            start_year, start_month = map(int, start_date.split("-"))

            end_date = input("End date (yyyy-mm): ")
            if end_date.lower() == "exit": sys.exit()
            end_year, end_month = map(int, end_date.split("-"))

            if end_year < start_year:
                raise Exception()
            elif end_year == start_year and end_month < start_month:
                raise Exception()
            break
        except:
            print("Incorrect format! Try Again.")

    all_data = {}
    bulletin_links = get_bulletin_links(start_year, start_month, end_year, end_month)

    print("\n\n")
    print(f"{len(bulletin_links)} security bulletins to scrape.")
    for link in bulletin_links:
        url, year, month = link
        print(f"Scraping: {year}-{month}. {bulletin_links.index(link)} / {len(bulletin_links)} done.", end="\r")
        time.sleep(random.uniform(1, 3))
        data = scrape_bulletin(url, year, month)

        if year not in all_data:
            all_data[year] = {}
        if month not in all_data[year]:
            all_data[year][month] = {}
        all_data[year][month] = data
        fh.save_to_json(all_data, "temp_asb_data.json")

    print()
    print(f"{len(bulletin_links)} / {len(bulletin_links)} done.")
    filename = input("Desired filename (.json): ")
    fh.save_to_json(all_data, filename)
    driver.quit()
    print("Scraping completed!")
    time.sleep(2)

