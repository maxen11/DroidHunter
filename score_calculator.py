
import file_handler as fh
import numpy as np
from datetime import datetime
from collections import Counter
import requests

def calculate_scores(file):
    data = fh.read_json_file(file)

    #### First pass over data to calculate type frequency and versions ########
    cve_types = []
    version_counts = {}
    poc_counts = {}

    for months in data.values():
        for cves in months.values():
            # Iterate over a list of keys so we can safely modify the dictionary
            for cve_id in list(cves.keys()):
                cve_entry = cves[cve_id]
                # Check if we have duplicate entries (stored as a list)
                if isinstance(cve_entry, list):
                    # For simplicity, use the first entry as a base and merge some fields:
                    base_detail = cve_entry[0]
                    
                    # For "Type", take the value from the first entry (or apply your own merging logic)
                    combined_type = base_detail.get("Type", "Unknown")
                    
                    # Aggregate updated AOSP versions and PoC links from all duplicates
                    all_versions = []
                    all_pocs = []
                    for detail in cve_entry:
                        versions = detail.get("Updated AOSP versions", "")
                        if versions:
                            # Split and strip each version
                            all_versions.extend([v.strip() for v in versions.split(",") if v.strip()])
                        pocs = detail.get("PoC_Links", [])
                        if pocs:
                            all_pocs.extend(pocs)
                    
                    # Remove duplicates
                    all_versions = list(set(all_versions))
                    all_pocs = list(set(all_pocs))
                    
                    cve_types.append(combined_type)
                    version_counts[cve_id] = len(all_versions)
                    nr_pocs = len(all_pocs)
                    
                    if nr_pocs == 0:
                        # Remove the CVE if it has no PoC links
                        del cves[cve_id]
                    else:
                        poc_counts[cve_id] = nr_pocs
                        
                    # Optionally, merge the duplicate entries into one:
                    cves[cve_id] = {
                        **base_detail,
                        "Updated AOSP versions": ", ".join(all_versions),
                        "PoC_Links": all_pocs
                    }
                else:
                    # Process the single dictionary case
                    cve_details = cve_entry
                    cve_types.append(cve_details.get("Type", "Unknown"))

                    versions_str = cve_details.get("Updated AOSP versions", "")
                    affected_versions = versions_str.split(",") if versions_str else []
                    version_counts[cve_id] = len(affected_versions)

                    pocs = cve_details.get("PoC_Links", [])
                    nr_pocs = len(pocs)
                    if nr_pocs == 0:
                        # Remove the CVE if it has no PoC links
                        del cves[cve_id]
                    else:
                        poc_counts[cve_id] = nr_pocs

    # Continue processing the remaining scoring logic...
    type_frequencies = Counter(cve_types)
    max_frequency = max(type_frequencies.values())
    max_versions = max(version_counts.values()) if version_counts else 0
    max_nr_pocs = max(poc_counts.values()) if poc_counts else 0

    # Define your weights
    weights = {
        "Sr": 2.1,   # Recency
        "Ss": 0.6,   # CVSS score
        "Se": 2.1,   # Exploitability
        "Sp": 2.1,   # PoC Availability
        "Sv": 1.2    # Affects multiple versions
    }

    scores = {}
    skipped_cves = 0
    for year, months in data.items():
        for month, cves in months.items():
            for cve_id, cve_details in cves.items():
                if "NVD_Data" in cve_details and cve_details["NVD_Data"]:
                    NVD_Data = cve_details["NVD_Data"]
                    impact = NVD_Data["impact"]
                    scores["Sr"] = calc_S_r(cve_details["publishedDate"])

                    if "baseMetricV3" in impact:
                        baseMetric = impact["baseMetricV3"]
                        cvss = baseMetric.get("cvssV3", {})
                        baseScore = cvss.get("baseScore", 0)
                        vectorString = cvss.get("vectorString", "")
                    elif "baseMetricV2" in impact:
                        baseMetric = impact["baseMetricV2"]
                        cvss = baseMetric.get("cvssV2", {})
                        baseScore = cvss.get("baseScore", 0)
                        vectorString = cvss.get("vectorString", "")
                    else:
                        baseScore = 0
                        vectorString = ""
                    #calc_S_epss(cve_id)
                    #print(cve_id)
                    scores["Ss"] = calc_S_s(baseScore)
                    #scores["Sac"] = calc_S_ac(vectorString)
                    versions_str = cve_details.get("Updated AOSP versions", "")
                    affected_versions = len(versions_str.split(",")) if versions_str else 0
                    scores["Sv"] = calc_S_v(affected_versions, max_versions)
                    scores["Se"] = calc_S_e2(NVD_Data["impact"])
                    scores["Sp"] = calc_S_p(len(cve_details["PoC_Links"]))
                    
                    final_score = calc_final_score(weights, scores)
                    cve_details["Priority Score"] = final_score
                else:
                    skipped_cves += 1
    print(f"{skipped_cves} CVEs Skipped.")
    
    print("\nScore calculation complete.")
    filename = input("Desired filename (.json): ")
    fh.save_to_json(data, filename)


def calc_S_e2(impact):
    if "baseMetricV3" in impact:
        return impact["baseMetricV3"]["exploitabilityScore"]/10
    elif "baseMetricV2" in impact:
        return impact["baseMetricV2"]["exploitabilityScore"]/10
    
import math

import math

def calc_S_p(cve_nr_pocs):
    """
    Calculate a PoC score using a logistic function.
    
    Parameters:
      - cve_nr_pocs: Number of PoCs for a CVE.
      - k: Controls the steepness of the curve.
      - x0: The midpoint (PoC count at which score is 0.5).
      
    Returns:
      A score between 0 and 1.
    """

    k=0.5
    x0=3
    if cve_nr_pocs <= 0:
        return 0
    score = 1 / (1 + math.exp(-k * (cve_nr_pocs - x0)))
    return score



# Calculate Recency Score
def calc_S_r(time):
    # Decay factor
    recency_lambda = 0.025 
    # ln 2 / 24 = 0.029, halflife of 2 years
    # ln 2 / 36 = 0.019, halflife 3 years
    # Halflife of 2-3 years makes sense based on support windows from Android manufactuers
    
    #input_date = datetime.fromisoformat(time)
    year = int(time[:4])   # Extracts "2015" and converts to int
    month = int(time[5:7]) # Extracts "

    now = datetime.now()
    # Age of CVE in months from date published
    t = (now.year - year) * 12 + (now.month - month)
    
    # The Recency Score
    Sr = np.exp(-recency_lambda*t)
    return Sr

# CVSS Severity Score
def calc_S_s(cvss_score):
    return cvss_score/10


def calc_S_ac(vectorString):
    if vectorString.startswith("CVSS:3."):
        parts = vectorString.split("/")
        cvss_dict = {}
        for part in parts[1:]:  # skip the "CVSS:3.x" part
            try:
                key, value = part.split(":")
                cvss_dict[key] = value
            except ValueError:
                continue
        
        cvss_scores_v3 = {
            "AC": {"L": 1.0, "H": 0.5}
        }
        AC_score = cvss_scores_v3["AC"].get(cvss_dict.get("AC"), 0)
        return AC_score
    elif "Au:" in vectorString:
        cvss_scores_v2 = {
            "AC": {"L": 1.0, "M": 0.75, "H": 0.5},
        }
        parts = vectorString.split("/")
        cvss_dict = {}
        for part in parts:
            try:
                key, value = part.split(":")
                cvss_dict[key] = value
            except ValueError:
                continue
        AC_score = cvss_scores_v2["AC"].get(cvss_dict.get("AC"), 0)
        return AC_score
# Exploitability Score
def calc_S_e(vectorString):
    # Check if this is a CVSSv3 vector string
    if vectorString.startswith("CVSS:3."):
        # Mapping for CVSSv3 for our exploitability calculation.
        cvss_scores_v3 = {
            "AV": {"N": 1.0, "A": 0.75, "L": 0.5, "P": 0.2},
            "AC": {"L": 1.0, "H": 0.5},
            "PR": {"N": 1.0, "L": 0.75, "H": 0.5},
            "UI": {"N": 1.0, "R": 0.5}
        }
        parts = vectorString.split("/")
        cvss_dict = {}
        for part in parts[1:]:  # skip the "CVSS:3.x" part
            try:
                key, value = part.split(":")
                cvss_dict[key] = value
            except ValueError:
                continue
        AV = cvss_scores_v3["AV"].get(cvss_dict.get("AV"), 0)
        AC = cvss_scores_v3["AC"].get(cvss_dict.get("AC"), 0)
        PR = cvss_scores_v3["PR"].get(cvss_dict.get("PR"), 0)
        UI = cvss_scores_v3["UI"].get(cvss_dict.get("UI"), 0)
        return (AV + AC + PR + UI) / 4
    # Otherwise, assume CVSSv2 if "Au:" is in the vector string
    elif "Au:" in vectorString:
        # Mapping for CVSSv2 metrics
        cvss_scores_v2 = {
            "AV": {"N": 1.0, "A": 0.646, "L": 0.395},
            "AC": {"L": 0.71, "M": 0.61, "H": 0.35},
            "Au": {"N": 0.704, "S": 0.56, "M": 0.45}
        }
        parts = vectorString.split("/")
        cvss_dict = {}
        for part in parts:
            try:
                key, value = part.split(":")
                cvss_dict[key] = value
            except ValueError:
                continue
        AV = cvss_scores_v2["AV"].get(cvss_dict.get("AV"), 0)
        AC = cvss_scores_v2["AC"].get(cvss_dict.get("AC"), 0)
        Au = cvss_scores_v2["Au"].get(cvss_dict.get("Au"), 0)
        return (AV + AC + Au) / 3
    else:
        return 0



def insert_PoC_availability():
    pass

def calc_S_d(type_frequency, max_frequency):
    return type_frequency/max_frequency

def calc_S_v(affected_versions, max_versions):
    return affected_versions / max_versions if max_versions > 0 else 0 

def calc_final_score(weights, scores):
    final_score = 0
    count = 0
    stored_variables = {}
    for variable in scores.keys():
        count+=1
        final_score+=weights[variable]*scores[variable]
        stored_variables[f"{variable}:W"] = f"{round(scores[variable],2)}:{weights[variable]}"
    final_score = round(final_score/count, 2) * int(bool(scores["Sp"]))
    final_dict = {
        "Score": final_score,
        "Variables": stored_variables
    }
    return final_dict

def calc_S_epss(cve_id):
    url = f"https://api.first.org/data/v1/epss?cve_id={cve_id}"
    response = requests.get(url)
    if response.status_code == 200:
        epss_data = response.json()
        print(epss_data)
    else:
        print("Error:", response.status_code)

