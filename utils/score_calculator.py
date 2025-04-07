import utils.file_handler as fh
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
    """weights = {
        "Sr": 2.1,   # Recency
        "Ss": 0.6,   # CVSS Severity Score
        "Se": 2.1,   # Exploitability
        "Sp": 2.1,   # PoC Availability
        "Sv": 1.2    # Affects multiple versions
    }"""

    weights = choose_weights()
    if not weights:
        return

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
    final_score = round(final_score / count, 2) #* int(bool(scores["Sp"]))              ##### COMMENT THIS IN/OUT TO FILTER OUT THOSE WITHOUT POC
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

def choose_weights():
    """
    Choose a set of weights based on the scoring profile.
    
    Profiles:
      - researcher: Prioritizes recency and severity.
      - redteam: Prioritizes exploitability and PoC availability.
      - blueteam: Emphasizes affected versions and balanced metrics.
      - default: A balanced profile.
    """
    while True:
        options = ["researcher", "redteam", "blueteam", "default", "custom", "Exit"]
        print("\n-- Scoring Profiles --")
        for i, option in enumerate(options, start=1):
            print(f"\t{i}. {option}")
        choice = input(f"Enter a scoring profile:  (1-{len(options)}): ")
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            profile = options[int(choice) - 1]
            if profile == "custom":  
                weights = {}
                for metric in ["Sr", "Ss", "Se", "Sp", "Sv"]:
                    while True:
                        try:
                            weight = float(input(f"Enter weight for {metric} (0-5): "))
                            if 0 <= weight <= 5:
                                weights[metric] = weight
                                break
                            else:
                                print("Weight must be between 0 and 5.")
                        except ValueError:
                            print("Invalid input. Please enter a number.")
                return weights
            elif profile == "exit":
                print("Exiting...")
                return None
            else:
                break

    if profile == "researcher":
        weights = {
            "Sr": 2.5,
            "Ss": 2.0,
            "Se": 1.0,
            "Sp": 0.5,
            "Sv": 1.0
        }
    elif profile == "redteam":
        weights = {
            "Sr": 1.0,
            "Ss": 0.5,
            "Se": 3.0,
            "Sp": 3.0,
            "Sv": 0.5
        }
    elif profile == "blueteam":
        weights = {
            "Sr": 2.0,
            "Ss": 1.5,
            "Se": 1.5,
            "Sp": 1.0,
            "Sv": 2.0
        }
    else:  # default
        weights = {
            "Sr": 2.1,
            "Ss": 0.6,
            "Se": 2.1,
            "Sp": 2.1,
            "Sv": 1.2
        }
    return weights

## Next on to-do:
"""
#parse links found in github repos, and check what they could be through keyword search for things like blog, writeup, exploit, project zero etc
GitHub PoCs often act as gateways to:

Better explanations

Original exploit authors

Chain exploits

Custom tooling

Disclosure timelines

These links aren’t always indexed elsewhere, but they often include:

"blog" (e.g., blog.zimperium.com)

"projectzero"

"research" or "paper" or "post"

"demo" or "youtube" (some PoCs demo a full chain)

"gist" (e.g., mini writeups or single-line PoCs)

Implementation Plan (Enrichment Pipeline Step)
After identifying GitHub PoC URLs:

Clone or fetch their README.md, *.md, or code comments.

Parse all links (http(s):// regex or Markdown link format).

Scan each link for keywords:
    interesting_keywords = ["projectzero", "blog", "writeup", "exploit", "demo", "paper", "research"]
    if any(kw in link.lower() for kw in interesting_keywords):
        mark_as_secondary_source(link)
Assign link type or tag:

link_type: "blog", "research", "paper", etc.

Store in a "Related_Links" field in your CVE metadata

Optional: Check for authorship / source:

"timwr" = likely by Tim Strazzere

"jcase" = often rooting exploits

"googleprojectzero" = ✨ top-tier


Use Case	Benefit
Add "Related_Links" to CVE output


interesting_keywords = [
    # PoC/Exploit
    "exploit", "poc", "proof-of-concept", "demo", "payload", "shellcode", "rce", "lpe",
    # Analysis
    "writeup", "analysis", "reversing", "deep-dive", "patch-analysis", "walkthrough",
    # Research
    "research", "whitepaper", "blackhat", "defcon", "slides", "conference", "presentation",
    # Bug types
    "vuln", "bug", "use-after-free", "race-condition", "infoleak", "overflow", "bypass",
    # Trusted sources
    "projectzero", "timwr", "checkra1n", "mandiant", "fireeye", "nccgroup", "zdi", "zerodium",
    # Platforms
    "github.io", "blogspot", "wordpress", "medium", "substack", "labs",
    # Videos
    "youtube", "vimeo", "video", "demonstration",
    # Tools
    "metasploit", "frida", "ghidra", "burpsuite", "ida", "nuclei"
]

Exploit / PoC-related

exploit
poc
proof-of-concept
demo
code
payload
shellcode
exploitdb
remote-code-execution
local-privilege-escalation
rce
lpe
arbitrary-code
cve
cve-202

Writeups & Analysis

writeup
walkthrough
analysis
breakdown
reversing
debug
explained
technical
explanation
review
deep-dive
vuln-analysis
details
how-it-works
step-by-step
patch-analysis
post-mortem

Research & Whitepapers

research
whitepaper
paper
conference
blackhat
defcon
hitcon
cansecwest
rootcon
publication
slides
presentation
talk
speaker
lab
internals

Vulnerability & Bug Discovery
bug
vuln
vulnerability
discovery
security-issue
misuse
misconfiguration
kernel-bug
heap-overflow
stack-overflow
race-condition
use-after-free
double-free
infoleak
sandbox-escape
bypass
privilege-escalation
memory-corruption
zero-day

Authors / Repos / Institutions
projectzero
googleprojectzero
timwr
jcase
aleph1
nils
leviathan
nightwatchcyber
threatpost
clementle
strazzere
vulnlab
kryptowire
checkra1n
zcool
exodusintel
mandiant
fireeye
qualys
nccgroup
zdi
zerodium
offsec
hackthebox


Domain / Hostnames / Platforms
blog
medium
github.io
gist
notion.so
research.checkpoint
research.samsung
labs
securitylab
blogspot
weebly
substack
wordpress


Videos, Demos, Presentations
youtube
video
vimeo
recording
livestream
presentation
demonstration


Exploit Tooling
metasploit
msf
burpsuite
frida
ghidra
ida
radare
android_debug
nuclei
scanner

"""

## Future work:
"""
# - Add a scoring function for the CVE type (e.g., "RCE", "DoS", etc.)
# - Add a scoring function for the CVE's affected versions (e.g., "Android 10", "Android 11", etc.)
# - Add a scoring function for the CVE's affected components (e.g., "System", "Framework", etc.)
# - Add a scoring function for the CVE's EPSS score (if available)
# - Add a scoring function for the Type frequency (e.g., "RCE", "DoS", etc.)
"""

# GitHub PoC Quality and Signs of abandonment
"""
#GitHub repo stars ("PoC repo stars")
#Higher star count = more usage, visibility, or trust.
#GitHub API (no scraping needed):
# https://api.github.com/repos/<owner>/<repo>/stargazers
# #GitHub repo forks ("PoC repo forks")
#Higher fork count = more usage, visibility, or trust.

# Filter PoCs for signs of abandonment: keywords like "deprecated", "archived", "unmaintained", etc.
# Check for recent activity: last commit date, last issue comment, etc.
# Check for community engagement: number of stars, forks, issues, etc.
"""

# Metasploit & Exploit Kits  
"""
#Publicly queryable via Rapid7’s Metasploit Framework repo
#You can clone and grep cve-YYYY-NNNN or query via:
#search cve:2017-0144 inside Metasploit CLI
#Or use: Metasploit-Module-Search JSON dump + community tools
#To automate:
#Clone repo or use an unofficial API (like msfdb)
#Build index of modules and match CVEs
""" 

# Other Exploit Feeds / Aggregators
"""
#You can crawl / parse:
#0day.today
#Packet Storm
#CXSecurity / Vulners.com (has API!)
#VulnCoDB (CVE → exploit mapping, paywalled but has open parts)
"""


# Threat Intelligence / Exploited-In-The-Wild
""""
#CISA’s Known Exploited Vulnerabilities Catalog
#Official U.S. gov catalog:
#https://www.cisa.gov/known-exploited-vulnerabilities-catalog
#JSON feed:
#https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
#You can:
#Parse this list
#Match your CVEs against it
#Add a boolean flag exploited_in_the_wild: true and/or score bonus
"""

#MITRE ATT&CK Mappings
"""
#Some CVEs are tied to ATT&CK TTPs (especially in Mandiant / Google TAG reports)
#Use:
#ATT&CK CVE mappings
#APT group mappings
"""

# chained_cve_bonus 
"""
This concept rewards CVEs that:

Share the same Android Security Bulletin category (e.g., “Framework”)

Are commonly used together (RCE + privilege escalation)

You can implement it by:

Method 1: Category Collisions

        for cve_id, details in cve_data.items():
            if details["Category"] in multiple_high_scoring_cves:
                bonus += 0.1  # 10% bump if same category is used often

Method 2: Known Chain Tags (harder but possible)
If any repo, write-up, or exploit mentions chain, sandbox escape, or multiple CVEs:

Flag CVEs mentioned alongside others

Use blog references (where available) or PoC descriptions
You could also simulate chains:
CVE A = sandbox escape
CVE B = kernel exploit
Same device → give a combined priority score
"""