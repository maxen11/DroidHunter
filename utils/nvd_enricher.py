import requests
import file_handler as fh
import time
import re
import os
import datetime
import zipfile
from pathlib import Path
import sys
import random

cve_pattern = re.compile(r"^CVE-\d{4}-\d+")

# Global cache to store the index (mapping of CVE ID -> 2.0 vulnerability item) for each year.
year_index_cache = {}

def print_progress(message):
    """Overwrite the terminal line with progress info."""
    sys.stdout.write("\r\033[2K" + message)
    sys.stdout.flush()

def download_and_extract(year, data_folder="CVE-Data"):
    """
    Download and extract NVD JSON 2.0 ZIP for a given year.
    Includes retry and throttling to avoid Cloudflare blocking.
    """
    if not os.path.exists(data_folder):
        os.makedirs(data_folder)

    url = f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.zip"
    zip_filename = os.path.join(data_folder, f"nvdcve-2.0-{year}.json.zip")
    json_filename = os.path.join(data_folder, f"nvdcve-2.0-{year}.json")

    if os.path.exists(json_filename):
        print_progress(f"[{year}] JSON file already exists. Skipping download.")
        time.sleep(0.5)
        return

    print_progress(f"[{year}] Downloading: {url}")
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux arm64; rv:131.0) Gecko/20100101 Firefox/131.0",
        "Accept": "application/zip,application/octet-stream;q=0.9,*/*;q=0.8",
        "Referer": "https://nvd.nist.gov/",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
    }

    # Retry with exponential backoff
    for attempt in range(5):
        try:
            response = requests.get(url, headers=headers, timeout=60)
            response.raise_for_status()
            with open(zip_filename, "wb") as f:
                f.write(response.content)
            break
        except requests.RequestException as e:
            wait_time = 2 ** attempt + random.uniform(0, 1.0)
            print_progress(f"[{year}] Failed to download ({e}), retrying in {int(wait_time)}s...")
            time.sleep(wait_time)
    else:
        print_progress(f"[{year}] Giving up after multiple failures.")
        return

    # Extract the zip file
    try:
        with zipfile.ZipFile(zip_filename, "r") as zip_ref:
            zip_ref.extractall(data_folder)
        print_progress(f"[{year}] Downloaded and extracted successfully.")
        time.sleep(0.5)
    except zipfile.BadZipFile as e:
        print_progress(f"[{year}] Error unzipping file: {e}")
        time.sleep(0.5)
    finally:
        if os.path.exists(zip_filename):
            os.remove(zip_filename)

def get_year_from_cve(cve_id):
    try:
        return int(cve_id.split("-")[1])
    except (IndexError, ValueError):
        return None

def load_year_index(year, data_folder="CVE-Data"):
    """
    Loads JSON 2.0 data for a given year and maps CVE IDs -> vulnerability items.
    """
    file_name = f"nvdcve-2.0-{year}.json"
    try:
        nvd_data = fh.read_json_file(file_name, Path(data_folder))
    except FileNotFoundError:
        print_progress(f"File not found for year {year}: {file_name}")
        time.sleep(0.5)
        return {}

    index = {}
    for item in nvd_data.get("vulnerabilities", []):
        cve_id = item.get("cve", {}).get("id", "").strip().upper()
        if cve_id:
            index[cve_id] = item
    return index

def _pick_metric(metrics_list):
    """
    From a list of metric objects, prefer NVD Primary, else NVD, else first.
    Returns the chosen metric dict or None.
    """
    if not isinstance(metrics_list, list) or not metrics_list:
        return None
    primary = [m for m in metrics_list if m.get("source") == "nvd@nist.gov" and m.get("type") == "Primary"]
    if primary:
        return primary[0]
    nvd = [m for m in metrics_list if m.get("source") == "nvd@nist.gov"]
    if nvd:
        return nvd[0]
    return metrics_list[0]

def _metrics_2_impact(vuln_item):
    """
    Convert NVD 2.0 metrics into a JSON **1.1-compatible** "impact" structure:
      impact = {
        "baseMetricV3": {
          "cvssV3": { ... v3 fields ... },
          "exploitabilityScore": float|None,
          "impactScore": float|None
        },
        "baseMetricV2": {
          "cvssV2": { ... v2 fields ... },
          "severity": str|None,
          "exploitabilityScore": float|None,
          "impactScore": float|None,
          "acInsufInfo": bool|None,
          "obtainAllPrivilege": bool|None,
          "obtainUserPrivilege": bool|None,
          "obtainOtherPrivilege": bool|None,
          "userInteractionRequired": bool|None
        }
      }
    Only keys that can be populated from 2.0 are included.
    """
    metrics = vuln_item.get("cve", {}).get("metrics", {})
    impact = {}

    # ---- CVSS v3.x -> baseMetricV3.cvssV3 ----
    chosen_v31 = _pick_metric(metrics.get("cvssMetricV31"))
    chosen_v30 = _pick_metric(metrics.get("cvssMetricV30")) if not chosen_v31 else None
    chosen_v3 = chosen_v31 or chosen_v30
    if chosen_v3:
        cvss = chosen_v3.get("cvssData", {}) or {}
        # Build a 1.1-like cvssV3 dict
        cvssV3 = {
            "version": cvss.get("version"),
            "vectorString": cvss.get("vectorString"),
            "attackVector": cvss.get("attackVector"),
            "attackComplexity": cvss.get("attackComplexity"),
            "privilegesRequired": cvss.get("privilegesRequired"),
            "userInteraction": cvss.get("userInteraction"),
            # v3.x
            "scope": cvss.get("scope"),
            "confidentialityImpact": cvss.get("confidentialityImpact"),
            "integrityImpact": cvss.get("integrityImpact"),
            "availabilityImpact": cvss.get("availabilityImpact"),
            "baseScore": cvss.get("baseScore"),
            "baseSeverity": cvss.get("baseSeverity"),
        }
        impact["baseMetricV3"] = {
            "cvssV3": cvssV3,
            "exploitabilityScore": chosen_v3.get("exploitabilityScore"),
            "impactScore": chosen_v3.get("impactScore"),
        }

    # ---- CVSS v2 -> baseMetricV2.cvssV2 ----
    chosen_v2 = _pick_metric(metrics.get("cvssMetricV2"))
    if chosen_v2:
        cvss2 = chosen_v2.get("cvssData", {}) or {}
        cvssV2 = {
            "version": cvss2.get("version"),               # "2.0"
            "vectorString": cvss2.get("vectorString"),     # e.g., "AV:N/AC:L/Au:S/C:P/I:P/A:P"
            "accessVector": cvss2.get("accessVector"),
            "accessComplexity": cvss2.get("accessComplexity"),
            "authentication": cvss2.get("authentication"),
            "confidentialityImpact": cvss2.get("confidentialityImpact"),
            "integrityImpact": cvss2.get("integrityImpact"),
            "availabilityImpact": cvss2.get("availabilityImpact"),
            "baseScore": cvss2.get("baseScore"),
        }
        impact["baseMetricV2"] = {
            "cvssV2": cvssV2,
            "severity": chosen_v2.get("baseSeverity"),
            "exploitabilityScore": chosen_v2.get("exploitabilityScore"),
            "impactScore": chosen_v2.get("impactScore"),
            "acInsufInfo": chosen_v2.get("acInsufInfo"),
            "obtainAllPrivilege": chosen_v2.get("obtainAllPrivilege"),
            "obtainUserPrivilege": chosen_v2.get("obtainUserPrivilege"),
            "obtainOtherPrivilege": chosen_v2.get("obtainOtherPrivilege"),
            "userInteractionRequired": chosen_v2.get("userInteractionRequired"),
        }

    return impact

def get_cve_info(cve_id, current_year):
    """
    Retrieve CVE info from cached year files and return a dict that
    mirrors the old 1.1 structure: {"impact": {...}}.
    """
    cve_id_norm = cve_id.strip().upper()
    year = get_year_from_cve(cve_id_norm)
    if not year or year < 2015 or year > current_year:
        return None

    if year not in year_index_cache:
        year_index_cache[year] = load_year_index(year)
    item = year_index_cache[year].get(cve_id_norm)
    if not item:
        return None

    impact = _metrics_2_impact(item)
    if impact:
        return {"impact": impact}
    return None

def enrich_with_nvd(json_file):
    asb_data = fh.read_json_file(json_file)

    # Count CVEs (lists indicate duplicates)
    total_cves = 0
    for months in asb_data.values():
        for cves in months.values():
            for _, value in cves.items():
                total_cves += len(value) if isinstance(value, list) else 1

    processed_cves = 0
    start_time = time.time()
    Failed_CVEs = 0
    current_year = int(datetime.datetime.now().year)

    # Ensure the feed files are downloaded for all years.
    for year in range(2015, current_year + 1):
        download_and_extract(year, "CVE-Data")
        time.sleep(random.uniform(1, 3))  # throttle between downloads

    # Iterate over the input CVE data and enrich with NVD data.
    for period, months in asb_data.items():
        for month, cves in months.items():
            for cve_id, cve_details in cves.items():
                targets = cve_details if isinstance(cve_details, list) else [cve_details]
                for detail in targets:
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
                            # EXACT same contract as before: dict with "impact"
                            detail["NVD_Data"] = nvd_cve_data
                        else:
                            Failed_CVEs += 1

    print_progress("Successful enrichment!")
    print()
    filename = input("Input desired file name (.json): ")
    fh.save_to_json(asb_data, filename)

if __name__ == "__main__":
    enrich_with_nvd("input_file.json")

