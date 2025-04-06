import file_handler as fh
import numpy as np
from datetime import datetime
from collections import Counter
import requests
import math

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
                if isinstance(cve_entry, list):
                    base_detail = cve_entry[0]
                    combined_type = base_detail.get("Type", "Unknown")
                    all_versions = []
                    all_pocs = []
                    for detail in cve_entry:
                        versions = detail.get("Updated AOSP versions", "")
                        if versions:
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
                    
                    # Even if there are no PoCs, we keep the CVE (score will be 0 for PoC metric)
                    poc_counts[cve_id] = nr_pocs
                        
                    # Merge duplicate entries into one
                    cves[cve_id] = {
                        **base_detail,
                        "Updated AOSP versions": ", ".join(all_versions),
                        "PoC_Links": all_pocs
                    }
                else:
                    # Process single dictionary case
                    cve_details = cve_entry
                    cve_types.append(cve_details.get("Type", "Unknown"))
                    versions_str = cve_details.get("Updated AOSP versions", "")
                    affected_versions = versions_str.split(",") if versions_str else []
                    version_counts[cve_id] = len(affected_versions)
                    pocs = cve_details.get("PoC_Links", [])
                    poc_counts[cve_id] = len(pocs)

    type_frequencies = Counter(cve_types)
    max_frequency = max(type_frequencies.values()) if type_frequencies else 1
    max_versions = max(version_counts.values()) if version_counts else 1
    max_nr_pocs = max(poc_counts.values()) if poc_counts else 1

    # Define your weights for each scoring metric
    weights = {
        "Sr": 2.1,   # Recency
        "Ss": 0.6,   # CVSS Severity Score
        "Se": 2.1,   # Exploitability
        "Sp": 2.1,   # PoC Availability
        "Sv": 1.2    # Affects multiple versions
    }

    scores = {}
    # Process each CVE and calculate its individual scores
    for year, months in data.items():
        for month, cves in months.items():
            for cve_id, cve_details in cves.items():
                # Recency Score: if publishedDate is missing, score is 0.
                published_date = cve_details.get("publishedDate")
                scores["Sr"] = calc_S_r(published_date) if published_date else 0

                # CVSS related scores: if NVD_Data is missing or empty, set scores to 0.
                if "NVD_Data" in cve_details and cve_details["NVD_Data"]:
                    NVD_Data = cve_details["NVD_Data"]
                    impact = NVD_Data.get("impact", {})
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
                    scores["Ss"] = calc_S_s(baseScore)
                    scores["Se"] = calc_S_e2(impact)
                else:
                    scores["Ss"] = 0
                    scores["Se"] = 0

                # Affected Versions Score: if no version data, set to 0.
                versions_str = cve_details.get("Updated AOSP versions", "")
                affected_versions = len(versions_str.split(",")) if versions_str else 0
                scores["Sv"] = calc_S_v(affected_versions, max_versions)

                # PoC Availability Score: if missing PoC_Links, score is 0.
                poc_links = cve_details.get("PoC_Links", [])
                scores["Sp"] = calc_S_p(len(poc_links)) if poc_links else 0

                final_score = calc_final_score(weights, scores)
                cve_details["Priority Score"] = final_score

    print("\nScore calculation complete.")
    filename = input("Desired filename (.json): ")
    fh.save_to_json(data, filename)


def calc_S_e2(impact):
    """
    Calculate a normalized exploitability score.
    For CVSS v3, scales the score (max 8.22) to a 0–1 range.
    For CVSS v2, uses the score on a 0–1 range directly.
    """
    if "baseMetricV3" in impact:
        # Scale CVSS v3 score to a 0–10 range and then to 0–1
        return (impact["baseMetricV3"]["exploitabilityScore"] * (10 / 8.22)) / 10
    elif "baseMetricV2" in impact:
        # Normalize CVSS v2 score to a 0–1 range
        return impact["baseMetricV2"]["exploitabilityScore"] / 10
    else:
        return 0


def calc_S_p(cve_nr_pocs):
    """
    Calculate a PoC score using a logistic function.
    Returns a score between 0 and 1.
    """
    k = 0.5
    x0 = 3
    if cve_nr_pocs <= 0:
        return 0
    score = 1 / (1 + math.exp(-k * (cve_nr_pocs - x0)))
    return score


def calc_S_r(time):
    """
    Calculate a recency score using an exponential decay function.
    If time is missing or improperly formatted, returns 0.
    """
    recency_lambda = 0.025 
    try:
        year = int(time[:4])
        month = int(time[5:7])
    except (ValueError, TypeError):
        return 0

    now = datetime.now()
    t = (now.year - year) * 12 + (now.month - month)
    Sr = np.exp(-recency_lambda * t)
    return Sr


def calc_S_s(cvss_score):
    """
    Calculate the CVSS severity score on a 0–1 scale.
    """
    return cvss_score / 10


def calc_S_ac(vectorString):
    if vectorString.startswith("CVSS:3."):
        parts = vectorString.split("/")
        cvss_dict = {}
        for part in parts[1:]:
            try:
                key, value = part.split(":")
                cvss_dict[key] = value
            except ValueError:
                continue
        
        cvss_scores_v3 = {"AC": {"L": 1.0, "H": 0.5}}
        AC_score = cvss_scores_v3["AC"].get(cvss_dict.get("AC"), 0)
        return AC_score
    elif "Au:" in vectorString:
        cvss_scores_v2 = {"AC": {"L": 1.0, "M": 0.75, "H": 0.5}}
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
    else:
        return 0


def calc_S_e(vectorString):
    if vectorString.startswith("CVSS:3."):
        cvss_scores_v3 = {
            "AV": {"N": 1.0, "A": 0.75, "L": 0.5, "P": 0.2},
            "AC": {"L": 1.0, "H": 0.5},
            "PR": {"N": 1.0, "L": 0.75, "H": 0.5},
            "UI": {"N": 1.0, "R": 0.5}
        }
        parts = vectorString.split("/")
        cvss_dict = {}
        for part in parts[1:]:
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
    elif "Au:" in vectorString:
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


def calc_S_d(type_frequency, max_frequency):
    return type_frequency / max_frequency


def calc_S_v(affected_versions, max_versions):
    return affected_versions / max_versions if max_versions > 0 else 0 


def calc_final_score(weights, scores):
    """
    Combine all individual scores using the provided weights.
    The final score is the weighted average of scores, multiplied by
    a flag based on PoC availability (score is zero if PoC score is 0).
    """
    final_score = 0
    count = 0
    stored_variables = {}
    for variable in scores.keys():
        count += 1
        final_score += weights[variable] * scores[variable]
        stored_variables[f"{variable}:W"] = f"{round(scores[variable], 2)}:{weights[variable]}"
    final_score = round(final_score / count, 2) * int(bool(scores["Sp"]))
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
