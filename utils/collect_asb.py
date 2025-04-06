import time
from datetime import datetime
import utils.file_handler as fh
import random
import os
import sys

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.edge.service import Service
from selenium.webdriver.edge.options import Options

from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

from bs4 import BeautifulSoup
import pandas as pd

import re
import platform
from selenium.common.exceptions import SessionNotCreatedException


# Define a pattern for a valid CVE ID
#cve_pattern = re.compile(r"^CVE-\d{4}-\d+")

#sys.stderr = open(os.devnull, "w")
#f = open(os.devnull, "w")
#sys.stderr = f 

# Suppress WebDriver Manager logs
#os.environ["WDM_LOG_LEVEL"] = "0"
#os.environ["webdriver.edge.silent"] = "true"

# Configure Edge WebDriver options
edge_options = Options()
edge_options.add_argument("--log-level=3")  # Suppress most browser logs
edge_options.add_argument("--disable-logging")
edge_options.add_argument("--disable-usb-keyboard-detect")
edge_options.add_argument("--disable-usb-discovery")  # Prevents USB scanning logs
edge_options.add_argument("--disable-device-discovery-notifications")  # Stops USB logging
edge_options.add_argument("--disable-blink-features=AutomationControlled")  # Reduce bot detection
edge_options.add_argument("--headless")  # no UI
edge_options.add_argument("--disable-blink-features=AutomationControlled")  # Reduce bot detection
edge_options.add_argument("--no-sandbox")


system = platform.system()

if system == "Windows":
    service = Service("./drivers/edgedriver_win64.exe", log_output=None)
elif system == "Linux":
    service = Service("./drivers/edgedriver_linux64", log_output=None)
elif system == "Darwin":
    service = Service("./drivers/edgedriver_mac64_m1", log_output=None)
else:
    print("Unsupported OS")
    exit()


try:
    driver = webdriver.Edge(service=service, options=edge_options)
except SessionNotCreatedException as e:
    if "cannot find msedge binary" in str(e):
        print("Error: \nMicrosoft Edge is not installed or not in your PATH.")
        print("Please install it from https://www.microsoft.com/edge")
        print("Once installed, make sure 'msedge' is accessible from the terminal.")
        exit()
    else:
        raise  # Re-raise if it's a different session error

BASE_URL = "https://source.android.com"
BULLETIN_URL = "https://source.android.com/docs/security/bulletin"

def get_bulletin_links(start_year=2015, start_month=8, end_year=datetime.today().year, end_month=datetime.today().month):
    links = []

    for year in range(start_year, end_year + 1):
        if year == start_year:
            month_start = start_month 
        else:
            month_start = 1 
        
        if year == end_year:
            month_end = end_month  
        else:
            month_end = 12 
        for month in range(month_start, month_end + 1):
            links.append((f"{BULLETIN_URL}/{year}-{month:02d}-01", year, month))
       
#    print(links)
    return links

def scrape_bulletin(url, year, month):
    if url == "https://source.android.com/docs/security/bulletin/2016-04-01":
        url = "https://source.android.com/docs/security/bulletin/2016-04-02"
    try:
        driver.get(url)
        wait = WebDriverWait(driver, 20)
        # Wait for the table element that contains CVE data to appear
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
        #print(h3_elements)
        table_title = table_categories[table_index]
        cve_index = headers.index("CVE")

        for row in rows[1:]:
            cols = row.find_all("td")
            # Optionally handle rows with missing columns instead of skipping outright:
            if not cols:
                continue

            # Extract the potential CVE text from the relevant column:
            cve_text = cols[cve_index].text.strip() if len(cols) > cve_index else ""
            # Use re.search to find a valid CVE within the text
            match = re.search(r"CVE-\d{4}-\d+", cve_text)
            if not match:
                continue
            cve_id = match.group(0)

            # Build the row data dictionary.
            row_data = {header: col.text.strip() for header, col in zip(headers, cols)}
            row_data["Bulletin_URL"] = url
            row_data["Category"] = table_title
            row_data["publishedDate"] = f"{year}-{month:02d}"

            # Merge duplicate entries instead of overwriting:
            if cve_id in data:
                existing_entry = data[cve_id]
                # If it's not already a list, convert to list
                if not isinstance(existing_entry, list):
                    existing_entry = [existing_entry]
                # Append the new row data
                existing_entry.append(row_data)
                data[cve_id] = existing_entry
            else:
                data[cve_id] = row_data
                
        table_index+=1

    return data



def collect_asb_data():

    time.sleep(3)
    start_year, start_month, end_year, end_month = ...,...,...,...,
    while True:
        try:
            start_date = input("Start date (yyyy-mm): ")
            if start_date.lower()=="exit": sys.exit()
            start_year, start_month = map(int, start_date.split("-"))

            end_date = input("End date (yyyy-mm): ")
            if end_date.lower()=="exit": sys.exit()
            end_year, end_month = map(int, end_date.split("-"))

            if end_year < start_year:
                raise Exception()
            elif end_year == start_year and end_month < start_month:
                raise Exception()
            break
        except:
            print("Incorrect format! Try Again.")


    all_data = {}
    bulletin_links = get_bulletin_links(start_year,start_month,end_year,end_month)

    print("\n\n")
    print(f"{len(bulletin_links)} security bulletins to scrape.")
    for link in bulletin_links:
        url = link[0]
        year = link[1]
        month = link[2]

        print(f"Scraping: {year}-{month}. {bulletin_links.index(link)} / {len(bulletin_links)} done.", end="\r") 

        time.sleep(random.uniform(1, 3))  #  delay to prevent getting blocked
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

#if __name__ == "__main__":
#    main()
