import requests
import utils.file_handler as fh
import time
import re
import os
import datetime
import zipfile
from pathlib import Path
import sys

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
cve_pattern = re.compile(r"^CVE-\d{4}-\d+")

# Global cache to store the index (mapping of CVE ID -> item) for each year.
year_index_cache = {}

def print_progress(message):
    """
    Clears the current line using ANSI escape sequences and writes the new message.
    This should overwrite the previous line in most terminals.
    """
    # "\033[2K" clears the current line; "\r" returns carriage to beginning.
    sys.stdout.write("\r\033[2K" + message)
    sys.stdout.flush()

def download_and_extract(year, data_folder="CVE-Data"):
    # Create data folder if it doesn't exist.
    if not os.path.exists(data_folder):
        os.makedirs(data_folder)

    # Build URL and file names based on year.
    url = f"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.zip"
    zip_filename = os.path.join(data_folder, f"nvdcve-1.1-{year}.json.zip")
    json_filename = os.path.join(data_folder, f"nvdcve-1.1-{year}.json")
    # Check if the JSON file already exists.
    if os.path.exists(json_filename):
        print_progress(f"[{year}] JSON file already exists. Skipping download.")
        # Pause briefly so that the message is visible before overwriting.
        time.sleep(0.5)
        return

    print_progress(f"[{year}] Downloading: {url}")
    try:
        response = requests.get(url)
        response.raise_for_status()
    except requests.RequestException as e:
        print_progress(f"[{year}] Failed to download: {e}")
        time.sleep(0.5)
        return

    # Save the zip file.
    with open(zip_filename, "wb") as f:
        f.write(response.content)
    
    # Extract the zip file.
    try:
        with zipfile.ZipFile(zip_filename, "r") as zip_ref:
            zip_ref.extractall(data_folder)
        print_progress(f"[{year}] Downloaded and extracted successfully.")
        time.sleep(0.5)
    except zipfile.BadZipFile as e:
        print_progress(f"[{year}] Error unzipping file: {e}")
        time.sleep(0.5)
    finally:
        # Remove the zip file.
        if os.path.exists(zip_filename):
            os.remove(zip_filename)

def get_year_from_cve(cve_id):
    """
    Extracts the year from a CVE ID string (e.g., "CVE-2020-1234" -> 2020).
    """
    try:
        return int(cve_id.split("-")[1])
    except (IndexError, ValueError):
        return None

def load_year_index(year, data_folder="CVE-Data"):
    """
    Loads the JSON file for the given year and builds a dictionary mapping 
    each CVE ID to its item.
    """
    file_name = f"nvdcve-1.1-{year}.json"
    try:
        nvd_data = fh.read_json_file(file_name, Path(data_folder))
    except FileNotFoundError:
        print_progress(f"File not found for year {year}: {file_name}")
        time.sleep(0.5)
        return {}
    
    index = {}
    for item in nvd_data.get("CVE_Items", []):
        cve_id = item.get("cve", {}).get("CVE_data_meta", {}).get("ID", "").strip().upper()
        if cve_id:
            index[cve_id] = item
    return index

def get_cve_info(cve_id, current_year):
    """
    Retrieves CVE info by extracting the year from the CVE ID and then looking it up 
    in the cached index for that year. If not cached yet, it loads and caches the index.
    """
    cve_id_norm = cve_id.strip().upper()
    year = get_year_from_cve(cve_id_norm)
    if not year or year < 2015 or year > current_year:
        return None

    if year not in year_index_cache:
        # Use print_progress so that this message is on the same line.
        #print_progress(f"Loading and indexing data for year {year}...")
        year_index_cache[year] = load_year_index(year)
    item = year_index_cache[year].get(cve_id_norm)
    if item and "impact" in item and item["impact"]:
        return {"impact": item["impact"]}
    return None

def enrich_with_nvd(json_file):    
    asb_data = fh.read_json_file(json_file)
    
    # Calculate total CVEs (accounting for duplicates stored as lists)
    total_cves = 0
    for months in asb_data.values():
        for cves in months.values():
            for key, value in cves.items():
                if isinstance(value, list):
                    total_cves += len(value)
                else:
                    total_cves += 1

    processed_cves = 0 
    start_time = time.time()
    Failed_CVEs = 0
    current_year = int(datetime.datetime.now().year)
    
    # Ensure the feed files are downloaded for all years.
    for year in range(2015, current_year + 1):
        download_and_extract(year)

    # Iterate over the input CVE data and enrich with NVD data.
    for period, months in asb_data.items():
        for month, cves in months.items():
            for cve_id, cve_details in cves.items():
                # For duplicate entries stored as lists.
                if isinstance(cve_details, list):
                    for detail in cve_details:
                        if "NVD_Data" not in detail:
                            if not cve_pattern.match(cve_id):
                                continue
                            
                            processed_cves += 1
                            percentage_done = (processed_cves / total_cves) * 100
                            elapsed = time.time() - start_time
                            avg_time_per_cve = elapsed / processed_cves
                            remaining_cves = total_cves - processed_cves
                            estimated_time_left = remaining_cves * avg_time_per_cve
                            minutes, seconds = divmod(estimated_time_left, 60)
                            
                            progress_message = (
                                f"Processing {cve_id}... [{processed_cves}/{total_cves}] "
                                f"({percentage_done:.2f}%) - Estimated time left: {int(minutes)}m {int(seconds)}s. "
                                f"Nr Failed: {Failed_CVEs}"
                            )
                            print_progress(progress_message)
                            
                            nvd_cve_data = get_cve_info(cve_id, current_year)
                            if nvd_cve_data:
                                detail["NVD_Data"] = nvd_cve_data
                            else:
                                Failed_CVEs += 1
                else:
                    if "NVD_Data" not in cve_details:
                        if not cve_pattern.match(cve_id):
                            continue
                        
                        processed_cves += 1
                        percentage_done = (processed_cves / total_cves) * 100
                        elapsed = time.time() - start_time
                        avg_time_per_cve = elapsed / processed_cves
                        remaining_cves = total_cves - processed_cves
                        estimated_time_left = remaining_cves * avg_time_per_cve
                        minutes, seconds = divmod(estimated_time_left, 60)
                        
                        progress_message = (
                            f"Processing {cve_id}... [{processed_cves}/{total_cves}] "
                            f"({percentage_done:.2f}%) - Estimated time left: {int(minutes)}m {int(seconds)}s. "
                            f"Nr Failed: {Failed_CVEs}"
                        )
                        print_progress(progress_message)
                        
                        nvd_cve_data = get_cve_info(cve_id, current_year)
                        if nvd_cve_data:
                            cve_details["NVD_Data"] = nvd_cve_data
                        else:
                            Failed_CVEs += 1

    print_progress("Successful enrichment!")
    print()  # Ensure the final message is on its own line.
    filename = input("Input desired file name (.json): ")
    fh.save_to_json(asb_data, filename)

if __name__ == "__main__":
    # Example usage: provide your input JSON file containing the CVE data.
    enrich_with_nvd("input_file.json")
