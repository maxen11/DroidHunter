import os
import re
import json
import subprocess
import requests
from tqdm import tqdm
import cve_searchsploit as CS  # Ensure cve_searchsploit is installed if needed
import utils.file_handler as fh
from datetime import datetime
from urllib.parse import urlparse


STAR_CACHE = {}
#MAX_API_REQUESTS = 5000  # Set a limit for API requests to avoid hitting the rate limit
#GITHUB_API_URL = "https://api.github.com/graphql"


def get_rate_usage(token=None):
    """
    Returns a tuple:
      (used, remaining, limit, reset_time (datetime))
    """
    if token is None:
        token = os.getenv("GITHUB_TOKEN")

    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "RateLimitChecker"
    }
    if token:
        headers["Authorization"] = f"token {token}"

    resp = requests.get("https://api.github.com/rate_limit", headers=headers, timeout=5)
    resp.raise_for_status()
    data = resp.json()

    graphql = data["resources"]["graphql"]
    limit = graphql["limit"]
    remaining = graphql["remaining"]
    used = graphql["used"]
    reset_unix = graphql["reset"]
    reset_time = datetime.utcfromtimestamp(reset_unix)

    return used, remaining, limit, reset_time

GITHUB_API_TOKEN = os.getenv("GITHUB_TOKEN")
if not GITHUB_API_TOKEN:
    print("Warning: GITHUB_TOKEN environment variable not set. Limited API access may occur.")
API_REQUEST_COUNT, REMAINING_REQUESTS, MAX_API_REQUESTS, RESET_TIME = get_rate_usage(GITHUB_API_TOKEN) 
#GITHUB_REQUEST_BAR = tqdm(total=MAX_API_REQUESTS, desc="GitHub API requests", dynamic_ncols=True, position=API_REQUEST_COUNT, leave=False)
GITHUB_REQUEST_BAR = tqdm(
    total=MAX_API_REQUESTS,
    initial=API_REQUEST_COUNT,
    desc="GitHub API requests",
    dynamic_ncols=True,
    leave=False
)

def clean_url(url):
    """
    Remove common trailing punctuation that might be added by markdown formatting.
    """
    # Remove common markdown wrapping characters.
    return url.strip("[]()<>").strip()

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

from urllib.parse import urlparse

def is_regular_github_repo(url):
    """
    Returns True if the URL is a regular GitHub repository URL 
    (e.g. https://github.com/owner/repo) and not from subdomains (e.g., gist.github.com)
    or is malformed.
    """
    try:
        clean = clean_url(url)
        parsed = urlparse(clean)
    except Exception as e:
        # If the URL parsing fails (e.g. invalid IPv6), skip it.
        return False

    # Allow only exactly 'github.com'
    if parsed.netloc.lower() != "github.com":
        return False
    # The path should have at least two segments: owner and repo.
    parts = [p for p in parsed.path.split("/") if p]
    return len(parts) >= 2

def extract_related_links_from_text(text, category_keywords, interesting_keywords, exclusion_list):
    """
    Extracts HTTP/HTTPS links from text, filters/classifies them based on keywords,
    and augments GitHub repository URLs with the repository's star count.
    """
    url_pattern = r'https?://[^\s)"]+'
    raw_links = re.findall(url_pattern, text)
    related_links = []
    for link in raw_links:
        link = clean_url(link)
        if any(exclusion in link.lower() for exclusion in exclusion_list):
            continue
        if any(kw in link.lower() for kw in interesting_keywords):
            classification = classify_url(link, category_keywords)
            if not classification:
                # no category matched, so skip
                continue
            # For GitHub, get star count if applicable.
            stars = None
            if is_regular_github_repo(link):
                stars, readme = get_github_stars_and_readme(link)
            related_links.append({
                'url': link,
                'classification': classification,
                'stars': stars
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
    #raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/README.md"
    
    #response = requests.get(raw_url)
    #if response.status_code != 200:
    #    if branch == "master":
    #        branch = "main"
    #        raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/README.md"
    #        response = requests.get(raw_url)
    #    if response.status_code != 200:
    #        return []
    stars, content = get_github_stars_and_readme(repo_url)#response.text
    
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
    "exec", "exec-code", "cve", "cve-", "cve-20", "exploitkit", "exploit-chain", "weaponized", "evil", "exploitation",

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
        if  is_regular_github_repo(link["url"]):
            sub_links = crawl_repo_for_related_links(link["url"], depth=depth+1, max_depth=max_depth, visited=visited)
            all_links.extend(sub_links)

    return all_links
###################### PoC Enricher ######################

def get_poc_links_for_cve(cve_id, poc_in_github_dir='PoC-in-GitHub'):
    """
    Aggregates PoC links for a given CVE using local PoC-in-GitHub repository data.
    ExploitDB links are included and returned, augmented with star counts for GitHub pages.
    """
    poc_links = set()
    
    # --- 1. Use GitHub PoC Database to get Links ---
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
                            url = entry['html_url']
                            # Check if it's a GitHub URL
                            if  is_regular_github_repo(url):
                                stars, readme = get_github_stars_and_readme(url)
                                #print(f"\n\n\n\nStars found: {stars} for url: {url}")
                            else:
                                stars = None
                            # Instead of just storing the URL, store a dict
                            poc_links.add(json.dumps({
                                "url": url,
                                "stars": stars
                            }))
            except Exception as e:
                print(f"[!] Error reading {file_path}: {e}")
    # --- 2. Use cve_searchsploit to get Exploit-DB IDs and form URLs ---
    try:
        edb_ids = CS.edbid_from_cve(cve_id)
    except Exception as e:
        print(f"[!] Error using cve_searchsploit for {cve_id}: {e}")
        edb_ids = []

    for edb_id in edb_ids:
        # Standard Exploit-DB URL format:
        url = f"https://www.exploit-db.com/exploits/{edb_id}"
        poc_links.add(json.dumps({"url":url}))
    # Convert the set of JSON strings back to a list of dicts.

    result = [json.loads(item) for item in poc_links]
    return result


def extract_github_repo(url):
    """
    Extract the repository owner and name from a GitHub URL.
    The URL is first cleaned; then only the first two path segments are used.
    Returns (owner, repo) or (None, None) if not valid.
    """
    try:
        clean = clean_url(url)
        parsed = urlparse(clean)
    except Exception as e:
        return None, None

    if parsed.netloc.lower() != "github.com":
        return None, None
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        return None, None
    owner, repo = parts[0], parts[1]
    # Remove trailing .git if present.
    repo = repo.replace(".git", "")
    return owner, repo

def get_github_stars_and_readme(url, token=None):
    """
    Given a GitHub URL, extract the repository owner and name (after cleaning it).
    Query the GitHub API for the repository information (including stargazers_count).
    Uses a global cache to avoid repeated API calls for the same repository.
    Updates a global progress counter and a tqdm progress bar on every API request.
    If a personal access token is provided (or is in the GITHUB_TOKEN env variable),
    it is used for authentication.
    Returns the star count, or 0 if any issue occurs.
    """
    # First, ensure that this URL is a proper GitHub repo URL.
    if not is_regular_github_repo(url):
        return 0, ""

    owner, repo = extract_github_repo(url)
    if not owner or not repo:
        return 0, ""

    # Build a unique repo key to use in the global cache.
    repo_key = f"{owner}/{repo}"
    if repo_key in STAR_CACHE:
        return STAR_CACHE[repo_key][0], STAR_CACHE[repo_key][1]

    #api_url = f"https://api.github.com/repos/{owner}/{repo}"
    #headers = {
    #    "Accept": "application/vnd.github+json",
    #    "User-Agent": "MyGitHubStarsFetcher"
    #}
    # Use provided token or fall back to the GITHUB_TOKEN environment variable.
    owner, repo = extract_github_repo(url)
    if GITHUB_API_TOKEN is None:
        print("No GitHub token provided. Please set the GITHUB_TOKEN environment variable.")
        return 0, ""
    headers = {
        "Authorization": f"bearer {GITHUB_API_TOKEN}",
        "Accept": "application/vnd.github.v4+json",
        "User-Agent": "MyGitHubGraphQLClient"
    }


    global API_REQUEST_COUNT
    try:
        #response = requests.get(api_url, headers=headers, timeout=5)
        gql = """
            query($owner:String!, $name:String!) {
            repository(owner: $owner, name: $name) {
                stargazerCount

                readme_md:    object(expression: "HEAD:README.md")    { ... on Blob { text } }
                readme_MD:    object(expression: "HEAD:README.MD")    { ... on Blob { text } }
                readme_markdown: object(expression: "HEAD:README.markdown") { ... on Blob { text } }
                readme_rst:   object(expression: "HEAD:README.rst")   { ... on Blob { text } }
                readme_txt:   object(expression: "HEAD:README.txt")   { ... on Blob { text } }
            }
            }
            """

        variables = {"owner": owner, "name": repo}
        response = requests.post("https://api.github.com/graphql",
                            json={"query": gql, "variables": variables},
                            headers=headers,
                            timeout=5)

        # Each API call increments our counter and updates the progress bar.
        API_REQUEST_COUNT += 1
        #GITHUB_REQUEST_BAR.total += 1
        GITHUB_REQUEST_BAR.update(1)
        GITHUB_REQUEST_BAR.set_postfix(requests=API_REQUEST_COUNT)

        if response.status_code != 200:
            print("GitHub API returned status", response.status_code, "for", url, ":", response.text)
            return 0, ""

        payload = response.json()
        result = payload.get("data", {}).get("repository")
        if not isinstance(result, dict):
            # either the repo doesn't exist, or something went wrong
            STAR_CACHE[repo_key] = [0, ""]
            return 0, ""

        # 3) Safe to .get now
        stars = result.get("stargazerCount", 0)

        # pick whichever alias gave you text
        readme = ""
        for key in ("readme_md","readme_MD","readme_markdown","readme_rst","readme_txt"):
            blob = result.get(key)
            if blob and isinstance(blob, dict) and blob.get("text"):
                readme = blob["text"]
                break

        # cache & return
        STAR_CACHE[repo_key] = [stars, readme]


        #if response.status_code == 200:
        #    data = response.json()
        #    star_count = data.get("stargazers_count", 0)
        #    #print(json.dumps(data, indent=4, sort_keys=False))
        #    STAR_CACHE[repo_key] = star_count
        #    return star_count
        #else:
        #    print(f"GitHub API returned status {response.status_code} for {api_url}: {response.text} for url: {url}")
        #    STAR_CACHE[repo_key] = 0
        #    return 0
    except Exception as e:
        print("Exception encountered while fetching GitHub stars:", str(e))
        STAR_CACHE[repo_key] = [0, ""]
        return 0, ""
    #print("Stars and readme for: \n\n\n\n", stars, readme)
    return stars, readme


def poc_enricher(file):
    # Update the local PoC-in-GitHub repository before processing
    update_local_poc_repo()

    data = fh.read_json_file(file)
    print("Enriching with available PoCs...")

    # Loop through CVEs with progress bars
    for year in tqdm(data, desc="Processing years"):
        for month in tqdm(data[year], desc=f"Processing months in {year}", leave=False):
            for cve_id in tqdm(data[year][month], desc="Processing CVEs", leave=False):
                cve_details = data[year][month][cve_id]
               
                filtered_poc_links, all_unique_links = get_poc_links_and_related_links(cve_id)
                
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

def get_poc_links_and_related_links(cve_id):

    blacklisted_names = [
        "nidhihcl75", "hshivhare67", "Trinadh465", "pazhanivel07", "Satheesh575555",
        "uthrasri", "nidhihcl", "ShaikUsaf", "nanopathi", "skyformat99", "bb33bb",
        "packages_apps_Settings_AOSP10", "system_bt_AOSP10", "AOSP10", "aosp10",
        "AbrarKhan", "RenukaSelvar", "saurabh2088", "packages_providers", "Pazhanivelmani",
        "MssGmz99"
    ]

    poc_links = get_poc_links_for_cve(cve_id)
    # Access the URL from each dictionary when filtering blacklisted names
    filtered_poc_links = [link for link in poc_links if not any(name in link["url"] for name in blacklisted_names)]
    
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
        #print(filtered_link)
        # Use the "url" key to check for "exploit-db.com"
        #if "exploit-db.com" in filtered_link["url"].lower():
        #    continue  # Skip crawling ExploitDB links.
        related_links = crawl_repo_for_related_links(filtered_link["url"])

        #print("All related links: \n\n\n\n", related_links)

        # Add recursive method, to crawl related_links if they are GitHub links
        for link_info in related_links:
            url = link_info.get("url")
            classification = link_info.get("classification", {})
            for category, keywords in classification.items():
                if url not in all_unique_links[category]:
                    all_unique_links[category].append(url)

    # Filter out categories with no related links
    #all_unique_links = {key:value for key, value in all_unique_links.items() if value}
    return filtered_poc_links, all_unique_links
            

###################### Example Usage ######################

if __name__ == "__main__":
    # Example URLs; you can replace these with your actual links.
    test_urls = [
        "https://github.com/david415/scan_for_rfc5961]",
        "https://github.com/violentshell/rover].",
        "https://github.com/dirtycow/dirtycow.github.io/blob/master/pokemon.c",
        "https://github.com/dirtycow/dirtycow.github.io/wiki"
    ]
    for url in test_urls:
        stars, readme = get_github_stars_and_readme(url)
        print(f"URL: {url} -> Stars: {stars}")

    # Ensure to close the progress bar at the end.
    GITHUB_REQUEST_BAR.close()
