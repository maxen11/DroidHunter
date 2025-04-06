import os
import re
import json
import subprocess
import cve_searchsploit as CS  # Make sure to install and import cve_searchsploit
import file_handler as fh

def update_local_poc_repo(repo_url="https://github.com/nomi-sec/PoC-in-GitHub.git", local_dir="PoC-in-GitHub"):
    """
    Updates the local PoC-in-GitHub repository by checking for new commits.
    If the local repo doesn't exist, it will clone it. If it exists, it will check for updates
    and only pull if there are new commits.
    """
    if not os.path.exists(local_dir):
        # Clone the repository since the folder doesn't exist
        try:
            subprocess.check_call(["git", "clone", repo_url, local_dir])
            print(f"Cloned repository {repo_url} into {local_dir}")
        except Exception as e:
            print(f"[!] Error cloning repository: {e}")
    else:
        # Repository exists; change directory and check for updates
        try:
            current_dir = os.getcwd()
            os.chdir(local_dir)
            # Fetch the latest changes from origin
            subprocess.check_call(["git", "fetch"])
            # Get current local commit hash and remote commit hash
            local_hash = subprocess.check_output(["git", "rev-parse", "HEAD"]).strip().decode('utf-8')
            # Use the current branch tracking info (e.g., origin/main or origin/master)
            remote_hash = subprocess.check_output(["git", "rev-parse", "@{u}"]).strip().decode('utf-8')
            if local_hash != remote_hash:
                # Pull new changes if the hashes differ
                subprocess.check_call(["git", "pull"])
                print("Repository updated with new changes.")
            else:
                print("No updates available in the remote PoC repository.")
            os.chdir(current_dir)
        except subprocess.CalledProcessError as e:
            print(f"[!] Git command failed: {e}")
        except Exception as e:
            print(f"[!] Error updating repository: {e}")
    #print("Updating cve_searchsploit database...")
    #CS.update_db()

def poc_enricher(file):
    # Update the local PoC-in-GitHub repository before processing
    update_local_poc_repo()

    data = fh.read_json_file(file)
    print("Enriching with available PoCs...")
    # Names of people who post fixes for CVEs, will generate false positives otherwise
    blacklisted_names = [
        "nidhihcl75",
        "hshivhare67", 
        "Trinadh465",
        "pazhanivel07", 
        "Satheesh575555",
        "uthrasri",
        "nidhihcl",
        "ShaikUsaf",
        "nanopathi",
        "skyformat99",
        "bb33bb",
        "packages_apps_Settings_AOSP10",
        "system_bt_AOSP10",
        "AOSP10",
        "aosp10",
        "AbrarKhan",
        "RenukaSelvar",
        "saurabh2088",
        "packages_providers",
        "Pazhanivelmani",
        "MssGmz99"
    ]

    for year, months in data.items():
        for month, cves in months.items():
            for cve_id, cve_details in cves.items():
                poc_links = get_poc_links_for_cve(cve_id)

                # Remove links containing blacklisted names
                filtered_poc_links = [link for link in poc_links if not any(name in link for name in blacklisted_names)]

                # Check if cve_details is a list of dictionaries (due to duplicates)
                if isinstance(cve_details, list):
                    for detail in cve_details:
                        detail["PoC_Links"] = filtered_poc_links
                else:
                    cve_details["PoC_Links"] = filtered_poc_links
    new_file = input("New filename: ")
    fh.save_to_json(data, new_file)

def get_poc_links_for_cve(cve_id, poc_in_github_dir='PoC-in-GitHub'):
    """
    Aggregates PoC links for a given CVE using cve_searchsploit and a local PoC-in-GitHub repository.
    
    Args:
        cve_id (str): The CVE identifier (e.g. "CVE-2024-0044").
        poc_in_github_dir (str): Path to the local PoC-in-GitHub folder.
        
    Returns:
        list: A list of unique PoC URLs for the CVE.
    """
    poc_links = set()
    
    # --- 1. Use cve_searchsploit to get Exploit-DB IDs and form URLs ---
    try:
        edb_ids = CS.edbid_from_cve(cve_id)
    except Exception as e:
        print(f"[!] Error using cve_searchsploit for {cve_id}: {e}")
        edb_ids = []
    
    for edb_id in edb_ids:
        # Standard Exploit-DB URL format:
        url = f"https://www.exploit-db.com/exploits/{edb_id}"
        poc_links.add(url)
    
    # --- 2. Use PoC-in-GitHub data stored locally ---
    # Extract year from CVE (assuming format "CVE-YYYY-XXXX")
    year_match = re.match(r'CVE-(\d{4})-\d+', cve_id)
    if year_match:
        year = year_match.group(1)
        # Construct file path: e.g., PoC-in-GitHub/2024/CVE-2024-0044.json
        file_path = os.path.join(poc_in_github_dir, year, f"{cve_id}.json")
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    # Each entry in the JSON file is expected to have an "html_url" key.
                    for entry in data:
                        if 'html_url' in entry:
                            poc_links.add(entry['html_url'])
            except Exception as e:
                print(f"[!] Error reading {file_path}: {e}")
    return list(poc_links)

# Example usage:
if __name__ == "__main__":
    # Update the exploit-database mapping (if needed)
    print("Updating cve_searchsploit database...")
    CS.update_db()

    # Example CVE
    cve = "CVE-2024-0044"
    print(f"Aggregating PoC links for {cve}...")
    links = get_poc_links_for_cve(cve)
    if links:
        for link in links:
            print(link)
    else:
        print(f"No PoC links found for {cve}.")

    # Optionally, run the PoC enricher on a given JSON file
    # poc_enricher("path/to/your_file.json")
