import os
import re
import json
import subprocess
import requests
from tqdm import tqdm
import cve_searchsploit as CS  # Ensure cve_searchsploit is installed if needed
import utils.file_handler as fh

###################### PoC Repository Updater ######################

def update_local_poc_repo(repo_url="https://github.com/nomi-sec/PoC-in-GitHub.git", local_dir="PoC-in-GitHub"):
    """
    Updates the local PoC-in-GitHub repository by checking for new commits.
    If the local repo doesn't exist, it will clone it. If it exists, it will check for updates
    and only pull if there are new commits.
    """
    if not os.path.exists(local_dir):
        try:
            subprocess.check_call(["git", "clone", repo_url, local_dir])
        except Exception as e:
            print(f"[!] Error cloning repository: {e}")
    else:
        try:
            current_dir = os.getcwd()
            os.chdir(local_dir)
            subprocess.check_call(["git", "fetch"])
            local_hash = subprocess.check_output(["git", "rev-parse", "HEAD"]).strip().decode('utf-8')
            remote_hash = subprocess.check_output(["git", "rev-parse", "@{u}"]).strip().decode('utf-8')
            if local_hash != remote_hash:
                subprocess.check_call(["git", "pull"])
            os.chdir(current_dir)
        except subprocess.CalledProcessError as e:
            print(f"[!] Git command failed: {e}")
        except Exception as e:
            print(f"[!] Error updating repository: {e}")
    # Optionally update the cve_searchsploit database:
    # CS.update_db()

###################### GitHub Repo Link Classifier ######################

def classify_url(url, category_keywords):
    """
    Classifies a given URL based on the provided category keywords.
    Returns a dict mapping category names to matching keywords.
    """
    classification = {}
    url_lower = url.lower()
    for category, keywords in category_keywords.items():
        matches = []
        for keyword in keywords:
            if keyword in url_lower:
                matches.append(keyword)
        if matches:
            classification[category] = matches
    return classification

def extract_links(text):
    """
    Extract all HTTP/HTTPS links from the given text.
    """
    url_pattern = r'https?://[^\s)"]+'
    return re.findall(url_pattern, text)

def is_excluded_link(link, exclusion_list):
    """
    Returns True if the link contains any substring from the exclusion_list.
    """
    link_lower = link.lower()
    for exclusion in exclusion_list:
        if exclusion in link_lower:
            return True
    return False

def extract_related_links_from_text(text, category_keywords, interesting_keywords, exclusion_list):
    """
    Extracts links from text and filters/classifies them based on interesting keywords,
    while excluding links from common generic sites.
    """
    links = extract_links(text)
    related_links = []
    for link in links:
        if is_excluded_link(link, exclusion_list):
            continue
        if any(kw in link.lower() for kw in interesting_keywords):
            classification = classify_url(link, category_keywords)
            related_links.append({
                'url': link,
                'classification': classification
            })
    return related_links

def crawl_repo_for_related_links(repo_url, branch="master", depth=1, max_depth=2, visited=None):
    if visited is None:
        visited = set()
    if repo_url in visited or depth > max_depth:
        return []

    visited.add(repo_url)
    """
    Crawls a GitHub repository by fetching its README.md, then extracts and classifies outbound links.
    Tries 'master' first; if that fails, retries with 'main'. Silent on branch fallback.
    """
    parts = repo_url.rstrip("/").split("/")
    if len(parts) < 5:
        return []
    owner = parts[3]
    repo = parts[4]
    raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/README.md"
    
    response = requests.get(raw_url)
    if response.status_code != 200:
        if branch == "master":
            branch = "main"
            raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/README.md"
            response = requests.get(raw_url)
        if response.status_code != 200:
            return []
    content = response.text
    
    category_keywords = {
    "Exploit/PoC-related": [
        "exploit", "exploit-code", "poc", "proof-of-concept", "demo", "payload", "shellcode",
        "exploitdb", "remote-code-execution", "local-privilege-escalation", "code-execution",
        "arbitrary-code", "exec", "exec-code", "unauthorized-access", "rce", "lpe", "exploitkit",
        "exploit-chain", "weaponized", "initial-access", "pivot", "combo-exploit", "sandbox-bypass"
    ],
    "Writeups & Analysis": [
        "writeup", "write-up", "walkthrough", "analysis", "deep-dive", "reversing", "reversed", "debug",
        "debugging", "explained", "explanation", "breakdown", "patch-analysis", "vuln-analysis", "how-it-works",
        "step-by-step", "reverse-engineering", "diagnosis", "report", "post-mortem", "technical"
    ],
    "Research & Whitepapers": [
        "research", "whitepaper", "academic", "paper", "publication", "slides", "internals",
        "conference", "conf", "blackhat", "defcon", "hitcon", "cansecwest", "rootcon", "shmoocon",
        "ekoparty", "hardwear.io", "ccc", "talk", "speaker", "keynote"
    ],
    "Vulnerability & Bug Discovery": [
        "bug", "vuln", "vulnerability", "discovery", "security-issue", "zero-day", "0day", "misuse",
        "misconfiguration", "bypass", "sandbox-escape", "leak", "memory-corruption", "infoleak", "oob",
        "out-of-bounds", "overflow", "stack-overflow", "heap-overflow", "heap", "stack", "uaf",
        "use-after-free", "double-free", "race-condition", "type-confusion", "dangling-pointer", "toctou",
        "time-of-check", "integer-overflow", "buffer-overflow", "escalation", "privesc", "eop"
    ],
    "Authors / Repos / Institutions": [
        "projectzero", "googleprojectzero", "timwr", "jcase", "aleph1", "nils", "leviathan", "maddiestone",
        "strazzere", "natashenka", "nightwatchcyber", "threatpost", "clementle", "zcool", "kryptowire",
        "mandiant", "fireeye", "exodusintel", "nccgroup", "zdi", "zerodium", "qualys", "checkra1n",
        "crowdstrike", "intelsecurity", "symantec", "citadel", "offsec", "hackthebox", "bugcrowd",
        "intigriti", "hackerone", "tenable", "fortinet", "securelist", "maltrail", "phishlabs"
    ],
    "Domain / Hostnames / Platforms": [
        "github", "gist", "github.io", "gitlab", "repo", "repository", "sourcecode", "medium", "notion.so",
        "wordpress", "substack", "blog", "blogspot", "weebly", "research.checkpoint", "research.samsung",
        "securitylab", "labs", "raw.githubusercontent", "cdn.jsdelivr", "pastebin", "ngrok", "replit",
        "tinyhack"
    ],
    "Videos, Demos, Presentations": [
        "youtube", "yt", "video", "vimeo", "recording", "livestream", "presentation", "demonstration",
        "demo-video", "screenrec", "webinar", "vid"
    ],
    "Exploit Tooling": [
        "metasploit", "msf", "burpsuite", "frida", "ghidra", "ida", "radare", "angr", "qiling", "nmap",
        "tracee", "android_debug", "adb", "gdb", "gef", "pwndbg", "peda", "dwarf", "emulator", "smashing",
        "nuclei", "scanner", "vulnerabilityscanner", "automated", "checksec"
    ]
}

    """
    interesting_keywords = [
        "exploit", "poc", "proof-of-concept", "demo", "code", "payload", "shellcode",
        "exploitdb", "remote-code-execution", "local-privilege-escalation", "rce", "lpe",
        "arbitrary-code", "cve", "cve-202",
        "writeup", "walkthrough", "analysis", "breakdown", "reversing", "debug", "explained",
        "technical", "explanation", "review", "deep-dive", "vuln-analysis", "details",
        "how-it-works", "step-by-step", "patch-analysis", "post-mortem",
        "research", "whitepaper", "paper", "conference", "blackhat", "defcon", "hitcon",
        "cansecwest", "rootcon", "publication", "slides", "presentation", "talk", "speaker",
        "lab", "internals",
        "bug", "vuln", "vulnerability", "discovery", "security-issue", "misuse", "misconfiguration",
        "kernel-bug", "heap-overflow", "stack-overflow", "race-condition", "use-after-free",
        "double-free", "infoleak", "sandbox-escape", "bypass", "privilege-escalation",
        "memory-corruption", "zero-day",
        "projectzero", "googleprojectzero", "timwr", "jcase", "aleph1", "nils", "leviathan",
        "nightwatchcyber", "threatpost", "clementle", "strazzere", "vulnlab", "kryptowire",
        "checkra1n", "zcool", "exodusintel", "mandiant", "fireeye", "qualys", "nccgroup",
        "zdi", "zerodium", "offsec", "hackthebox",
        "blog", "medium", "github.io", "gist", "notion.so", "research.checkpoint", "research.samsung",
        "labs", "securitylab", "blogspot", "weebly", "substack", "wordpress",
        "youtube", "video", "vimeo", "recording", "livestream", "presentation", "demonstration",
        "metasploit", "msf", "burpsuite", "frida", "ghidra", "ida", "radare", "android_debug",
        "nuclei", "scanner",
        "tinyhack", "repo", "repository", "github"
    ]
    """

    interesting_keywords = [
    # Exploit / PoC-related
    "exploit", "exploit-code", "exploitdb", "poc", "proof-of-concept", "demo", "payload", "shellcode", 
    "remote-code-execution", "local-privilege-escalation", "code-execution", "arbitrary-code", "unauthorized-access",
    "exec", "exec-code", "cve", "cve-", "cve-20", "exploitkit", "exploit-chain", "weaponized",

    # Writeups & Analysis
    "writeup", "write-up", "walkthrough", "analysis", "deep-dive", "reversing", "reversed", "debug",
    "debugging", "explained", "explanation", "exploited", "breakdown", "patch-analysis", "vuln-analysis",
    "how-it-works", "step-by-step", "reverse-engineering", "diagnosis", "report", "post-mortem", "technical",

    # Research & Whitepapers
    "research", "whitepaper", "academic", "paper", "conference", "conf", "blackhat", "defcon", "hitcon", 
    "rootcon", "cansecwest", "shmoocon", "ekoparty", "hardwear.io", "ccc", "publication", "slides", 
    "talk", "speaker", "internals", "keynote",

    # Vulnerability & Bug Discovery
    "vuln", "vulnerability", "bug", "discovery", "security-issue", "zero-day", "0day", "misuse", 
    "misconfiguration", "bypass", "sandbox-escape", "sandbox", "leak", "memory-corruption", 
    "infoleak", "oob", "out-of-bounds", "overflow", "stack-overflow", "heap-overflow", "heap", "stack", 
    "uaf", "use-after-free", "double-free", "race-condition", "type-confusion", "dangling-pointer", 
    "toctou", "time-of-check", "integer-overflow", "buffer-overflow", "escalation", "privesc", "eop",

    # Platform / Component terms
    "android", "aosp", "init", "zygote", "selinux", "binder", "gralloc", "mediaserver", "system_server",
    "vendor", "trustzone", "qsee", "camera", "libstagefright", "ashmem", "services", "kernel", "syscall",

    # Authors / Orgs / Institutions
    "projectzero", "googleprojectzero", "timwr", "jcase", "aleph1", "nils", "leviathan", "maddiestone",
    "strazzere", "natashenka", "nightwatchcyber", "threatpost", "clementle", "zcool", "kryptowire",
    "mandiant", "fireeye", "exodusintel", "nccgroup", "zdi", "zerodium", "qualys", "checkra1n",
    "crowdstrike", "intelsecurity", "symantec", "citadel", "offsec", "hackthebox", "bugcrowd", "intigriti",
    "hackerone", "tenable", "fortinet", "securelist", "maltrail", "phishlabs",

    # Domains / Hosts / Platforms
    "github", "gist", "github.io", "gitlab", "repo", "repository", "sourcecode", "medium", "notion.so", 
    "wordpress", "substack", "blog", "blogspot", "weebly", "research.checkpoint", "research.samsung",
    "securitylab", "labs", "raw.githubusercontent", "cdn.jsdelivr", "pastebin", "ngrok", "replit", "tinyhack",

    # Videos / Demos / Presentations
    "youtube", "yt", "video", "vimeo", "recording", "livestream", "presentation", "demonstration", 
    "demo-video", "screenrec", "webinar", "vid",

    # Tooling & Exploit Frameworks
    "metasploit", "msf", "burpsuite", "frida", "ghidra", "ida", "radare", "angr", "qiling", 
    "nmap", "tracee", "android_debug", "adb", "gdb", "gef", "pwndbg", "peda", "dwarf", "emulator", 
    "smashing", "nuclei", "scanner", "vulnerabilityscanner", "automated", "checksec",

    # Disclosure / Patching / Advisory
    "patch", "patches", "advisory", "disclosure", "fix", "fixes", "update", "hotfix", "workaround", 
    "mitigation", "cvedetails", "vulners", "osvdb", "exploit-db", "packetstorm", "0day.today", "cisa", 
    "nvd", "mitre", "vulncode", "known-exploited", "kev", "tracked-as", "timeline", "responsible-disclosure",

    # Additional Signals
    "score", "cvss", "epss", "severity", "critical", "impact", "actively-exploited", "exploited-in-the-wild", 
    "chained", "chain", "multi-stage", "initial-access", "pivot", "combo-exploit", "sandbox-bypass",

    # Misc dev / GitHub activity
    "fork", "pull-request", "commit", "merge", "diff", "branch", "clone", "push", "release", "main", "master"
]


    
    exclusion_list = [
        "source.android.com/docs/security/bulletin",
        "nvd.nist.gov",
        "cve.mitre.org",
        "cisa.gov"
    ]
    
    related_links = extract_related_links_from_text(content, category_keywords, interesting_keywords, exclusion_list)
    all_links = related_links.copy()

    # Recurse on valid GitHub URLs only
    for link in related_links:
        if "github.com" in link["url"]:
            sub_links = crawl_repo_for_related_links(link["url"], depth=depth+1, max_depth=max_depth, visited=visited)
            all_links.extend(sub_links)

    return all_links
###################### PoC Enricher ######################

def get_poc_links_for_cve(cve_id, poc_in_github_dir='PoC-in-GitHub'):
    """
    Aggregates PoC links for a given CVE using local PoC-in-GitHub repository data.
    ExploitDB links are included and returned.
    """
    poc_links = set()
    
    # Use PoC-in-GitHub data stored locally
    year_match = re.match(r'CVE-(\d{4})-\d+', cve_id)
    if year_match:
        year = year_match.group(1)
        file_path = os.path.join(poc_in_github_dir, year, f"{cve_id}.json")
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for entry in data:
                        if 'html_url' in entry:
                            poc_links.add(entry['html_url'])
            except Exception as e:
                print(f"[!] Error reading {file_path}: {e}")
    return list(poc_links)

def poc_enricher(file):
    # Update the local PoC-in-GitHub repository before processing
    update_local_poc_repo()

    data = fh.read_json_file(file)
    print("Enriching with available PoCs...")
    
    blacklisted_names = [
        "nidhihcl75", "hshivhare67", "Trinadh465", "pazhanivel07", "Satheesh575555",
        "uthrasri", "nidhihcl", "ShaikUsaf", "nanopathi", "skyformat99", "bb33bb",
        "packages_apps_Settings_AOSP10", "system_bt_AOSP10", "AOSP10", "aosp10",
        "AbrarKhan", "RenukaSelvar", "saurabh2088", "packages_providers", "Pazhanivelmani",
        "MssGmz99"
    ]

    # Loop through CVEs with progress bars
    for year in tqdm(data, desc="Processing years"):
        for month in tqdm(data[year], desc=f"Processing months in {year}", leave=False):
            for cve_id in tqdm(data[year][month], desc="Processing CVEs", leave=False):
                cve_details = data[year][month][cve_id]
                poc_links = get_poc_links_for_cve(cve_id)
                filtered_poc_links = [link for link in poc_links if not any(name in link for name in blacklisted_names)]
                
                # Gather all unique related links from all filtered PoC URLs,
                # but skip crawling on ExploitDB links.
                all_unique_links = {
                    "Exploit/PoC-related": [],
                    "Writeups & Analysis": [],
                    "Research & Whitepapers": [],
                    "Vulnerability & Bug Discovery": [],
                    "Authors / Repos / Institutions": [],
                    "Domain / Hostnames / Platforms": [],
                    "Videos, Demos, Presentations": [],
                    "Exploit Tooling": []
                }
                
                for filtered_link in filtered_poc_links:
                    if "exploit-db.com" in filtered_link.lower():
                        continue  # Skip crawling ExploitDB links.
                    related_links = crawl_repo_for_related_links(filtered_link)
                    # Add recursive method, to crawl related_links if they are GitHub links

                    for link_info in related_links:
                        url = link_info.get("url")
                        classification = link_info.get("classification", {})
                        for category, keywords in classification.items():
                            if url not in all_unique_links[category]:
                                all_unique_links[category].append(url)
                
                # Update the CVE details with PoC and Related Links
                if isinstance(cve_details, list):
                    for detail in cve_details:
                        detail["PoC_Links"] = filtered_poc_links
                        if filtered_poc_links:
                            detail["Related_Links"] = all_unique_links
                else:
                    cve_details["PoC_Links"] = filtered_poc_links
                    if filtered_poc_links:
                        cve_details["Related_Links"] = all_unique_links

    new_file = input("New filename: ")
    fh.save_to_json(data, new_file)

###################### Example Usage ######################

if __name__ == "__main__":
    # Update cve_searchsploit database if needed
    print("Updating cve_searchsploit database...")
    CS.update_db()

    # Example: Aggregate PoC links for a specific CVE
    cve = "CVE-2024-0044"
    print(f"Aggregating PoC links for {cve}...")
    links = get_poc_links_for_cve(cve)
    if links:
        for link in links:
            print(link)
    else:
        print(f"No PoC links found for {cve}.")

    # Enrich a JSON file with PoC and related links
    poc_enricher("path/to/your_file.json")
