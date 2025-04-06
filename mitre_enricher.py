import requests
import file_handler as fh
import time
import random
import re

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
cve_pattern = re.compile(r"^CVE-\d{4}-\d+")

def load_all_nvd_data(years):
    all_cve_data = {}
    #print(years)
    for year in years:
        file_name = f"CVE-Data/nvdcve-1.1-{year}.json"
        nvd_data = fh.read_json_file(file_name)
        count = 0
        for item in nvd_data["CVE_Items"]:
            cve_id = item["cve"]["CVE_data_meta"]["ID"].strip().upper()
            all_cve_data[cve_id] = item
            count += 1
            if count == 1:
                all_cve_data[cve_id]
    return all_cve_data

def extract_cvss_v2():
    pass
def extreact_cvss_v3():
    pass

def get_cve_info(data, cve_id):
    """
    Retrieve CVE info from the pre-loaded data.
    """
    # Normalize the CVE ID
    cve_id_norm = cve_id.strip().upper()
    cve_item = data.get(cve_id_norm)
    if cve_item and "impact" in cve_item and cve_item["impact"]:
        return {
            "impact": cve_item["impact"],
        }
    else:
        #print(f"Failed to retrieve cvss data for {cve_id}")
        return None



def enrich_with_mitre(json_file):    
    asb_data = fh.read_json_file(json_file)
    
    # Calculate total CVEs accounting for duplicates stored as lists
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

    all_data = load_all_nvd_data([year for year in range(2015, 2025 + 1)])

    for year, months in asb_data.items():
        for month, cves in months.items():
            for cve_id, cve_details in cves.items():
                # Check if the CVE details is a list (duplicate entries)
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

                            print(f"Processing {cve_id}... [{processed_cves}/{total_cves}] ({percentage_done:.2f}%) - Estimated time left: {int(minutes)}m {int(seconds)}s. Nr Failed: {Failed_CVEs}", end="\r", flush=True)

                            nvd_cve_data = get_cve_info(all_data, cve_id)
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

                        print(f"Processing {cve_id}... [{processed_cves}/{total_cves}] ({percentage_done:.2f}%) - Estimated time left: {int(minutes)}m {int(seconds)}s. Nr Failed: {Failed_CVEs}", end="\r", flush=True)

                        nvd_cve_data = get_cve_info(all_data, cve_id)
                        if nvd_cve_data:
                            cve_details["NVD_Data"] = nvd_cve_data
                        else:
                            Failed_CVEs += 1

    print("\nSuccessful enrichment!")
    filename = input("Input desired file name (.json): ")
    fh.save_to_json(asb_data, filename)




def get_cve_info_from_api(cve_id, max_retries=5):
    url = NVD_API_URL + cve_id
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                      '(KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36'
        # Include an API key here if needed:
        # 'apiKey': 'YOUR_API_KEY'
    }
    
    retries = 0
    delay = 2  # initial delay in seconds
    while retries < max_retries:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 403:
            print(f"Received 403 for {cve_id}. Retrying in {delay} seconds... (Attempt {retries+1}/{max_retries})")
            time.sleep(delay)
            delay *= 2  # Exponential backoff
            retries += 1
        else:
            print(f"Error {response.status_code} for {cve_id}")
            return None
    print(f"Failed to retrieve data for {cve_id} after {max_retries} attempts.")
    return None