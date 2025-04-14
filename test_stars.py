import os
import re
import requests
from urllib.parse import urlparse

def extract_github_repo(url):
    """
    Extracts the repository owner and name from a GitHub URL.
    Returns (owner, repo) or (None, None) if the URL does not conform.
    """
    parsed = urlparse(url)
    if "github.com" not in parsed.netloc.lower():
        return None, None
    # Split the path into parts and ignore empty parts
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        return None, None
    owner, repo = parts[0], parts[1]
    # Remove trailing .git if present
    repo = repo.replace(".git", "")
    return owner, repo

def get_github_stars(url, token=None):
    """
    Given a GitHub URL, extract the repository owner and name, then fetch the
    stargazers_count via the GitHub API. If a personal access token is provided
    either as an argument or in the GITHUB_TOKEN environment variable, it will
    be used for authentication. Returns 0 if any error occurs or the URL doesn't match.
    """
    owner, repo = extract_github_repo(url)
    if not owner or not repo:
        return 0
    
    api_url = f"https://api.github.com/repos/{owner}/{repo}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "MyGitHubStarsFetcher"
    }
    
    # Use provided token or fall back to the environment variable
    if token is None:
        token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"token {token}"
    
    try:
        response = requests.get(api_url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data.get("stargazers_count", 0)
        else:
            print(f"GitHub API returned status {response.status_code} for {api_url}: {response.text}")
            return 0
    except Exception as e:
        print("Exception encountered while fetching GitHub stars:", str(e))
        return 0
if __name__ == "__main__":
    stars = get_github_stars("https://github.com/talbeerysec/BAD-WEBP-CVE-2023-4863")
    print(f"Nr of stars: {stars}")
