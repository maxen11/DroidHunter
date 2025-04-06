import re
import sys

def count_unique_cves(filename):
    # Regular expression for matching CVE identifiers (e.g., CVE-2021-1234)
    cve_pattern = re.compile(r'\bCVE-\d{4}-\d+\b', re.IGNORECASE)
    
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            content = file.read()
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        sys.exit(1)
    
    # Find all CVE matches and create a set to get unique instances
    matches = cve_pattern.findall(content)
    unique_cves = set(matches)
    
    return len(unique_cves)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <filename>")
        sys.exit(1)
    
    file_to_read = sys.argv[1]
    unique_count = count_unique_cves(file_to_read)
    print(f"Total unique CVEs found: {unique_count}")

