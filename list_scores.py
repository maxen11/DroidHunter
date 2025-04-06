import file_handler as fh
import pprint
import json
from datetime import datetime

# Global variables
timeframe_year_start = None
timeframe_year_end = None

def set_timeframe(start, end):
    global timeframe_year_start, timeframe_year_end
    now_year = datetime.now().year

    try:
        start = int(start)
        end = int(end)
    except ValueError:
        print("Error: Start and end must be integers.")
        return False

    if start < 2015:
        print("Error: Start year must be 2015 or later.")
        return False
    if end > now_year:
        print(f"Error: End year cannot be in the future (max {now_year}).")
        return False
    if start > end:
        print("Error: Start year cannot be after end year.")
        return False

    # Passed all checks
    timeframe_year_start = start
    timeframe_year_end = end
    return True

def get_timeframe():
    if timeframe_year_start is not None and timeframe_year_end is not None:
        return (timeframe_year_start, timeframe_year_end)
    else:
        return None
    
def is_year_in_timeframe(year_str):
    if timeframe_year_start is not None and timeframe_year_end is not None:
        try:
            year_int = int(year_str)
            return timeframe_year_start <= year_int <= timeframe_year_end
        except ValueError:
            return False
    return True

def lookup_cve(json_file, lookup_cve):
    data = fh.read_json_file(json_file)
    results = {}
    for year, months in data.items():
        for month, cves in months.items():
            for cve_id, cve_details in cves.items():
                if cve_id == lookup_cve:
                    results[cve_id] = cve_details
    print("ABRAKADABRA RESULTS \n\n\n")
    return results

def list_scores(file, amount):
    data = fh.read_json_file(file)
    scores_list = []

    for year in data:
        if not is_year_in_timeframe(year):
            continue
        for month in data[year]:
            for cve_id, cve_details in data[year][month].items():
                if "Priority Score" in cve_details:
                    score = cve_details["Priority Score"].get("Score", 0)
                    scores_list.append((cve_id, score))

    sorted_scores = sorted(scores_list, key=lambda x: x[1], reverse=True)

    print("CVE ID\t\tPriority Score")
    print("--------------------------------")
    for cve, score in sorted_scores[:amount]:
        print(f"{cve}\t{score}")


def list_top_amount_cve_details(file, amount):
    data = fh.read_json_file(file)
    scores_list = []

    for year in data:
        if not is_year_in_timeframe(year):
            continue
        for month in data[year]:
            for cve_id, cve_details in data[year][month].items():
                if "Priority Score" in cve_details:
                    score = cve_details["Priority Score"].get("Score", 0)
                    scores_list.append((cve_id, score, cve_details))

    sorted_scores = sorted(scores_list, key=lambda x: x[1], reverse=True)
    top_amount = sorted_scores[:amount]

    for cve_id, score, details in top_amount:
        print(f"CVE ID: {cve_id}")
        print(f"Priority Score: {score}")
        print("Details:")
        print(json.dumps(details, indent=4, sort_keys=False))
        print("-" * 40)



def list_top_5_by_type(file):
    data = fh.read_json_file(file)
    best_by_type = {}

    for year in data:
        if not is_year_in_timeframe(year):
            continue
        for month in data[year]:
            for cve_id, cve_details in data[year][month].items():
                cve_type = cve_details.get("Type", "Unknown")
                if "Priority Score" in cve_details:
                    score = cve_details["Priority Score"].get("Score", 0)
                    if cve_type not in best_by_type or score > best_by_type[cve_type][0]:
                        best_by_type[cve_type] = (score, cve_id, cve_details)

    best_list = [
        (cve_type, cve_id, score, details)
        for cve_type, (score, cve_id, details) in best_by_type.items()
    ]

    sorted_best = sorted(best_list, key=lambda x: x[2], reverse=True)

    print("Top 5 CVEs by Highest Score per Type:")
    print("======================================")
    for i, (cve_type, cve_id, score, details) in enumerate(sorted_best[:5], start=1):
        print(f"{i}. Type: {cve_type}")
        print(f"   CVE ID: {cve_id}")
        print(f"   Priority Score: {score}")
        print("   Details:")
        print(json.dumps(details, indent=4, sort_keys=False))
        print("-" * 40)


def list_best_by_type_all(file):
    """
    For each unique CVE type, find the CVE with the highest Priority Score and print all its details.
    """
    data = fh.read_json_file(file)
    best_by_type = {}  # Maps each type to a tuple: (score, cve_id, details)

    # Iterate over all CVEs in the data
    for year in data:
        if not is_year_in_timeframe(year):
            continue
        for month in data[year]:
            for cve_id, cve_details in data[year][month].items():
                # Get the type; default to "Unknown" if missing.
                cve_type = cve_details.get("Type", "Unknown")
                if "Priority Score" in cve_details:
                    score = cve_details["Priority Score"].get("Score", 0)
                    # If this type hasn't been seen or if this CVE's score is higher, update the record.
                    if cve_type not in best_by_type or score > best_by_type[cve_type][0]:
                        best_by_type[cve_type] = (score, cve_id, cve_details)
    
    # Print the best CVE for each type
    print("Best CVE per Type (All Details):")
    print("=" * 40)
    for cve_type, (score, cve_id, details) in best_by_type.items():
        print(f"Type: {cve_type}")
        print(f"CVE ID: {cve_id}")
        print(f"Priority Score: {score}")
        print("Details:")
        print(json.dumps(details, indent=4, sort_keys=False))
        print("-" * 40)


def list_top_amount_by_type(file, amount):
    """
    For each CVE type, group the CVEs and print the top 3 based on Priority Score.
    Only the CVE ID, score, and type are displayed.
    """
    data = fh.read_json_file(file)
    grouped = {}  # Maps each type to a list of tuples: (score, cve_id)

    # Group CVEs by type
    for year in data:
        if not is_year_in_timeframe(year):
            continue
        for month in data[year]:
            for cve_id, cve_details in data[year][month].items():
                cve_type = cve_details.get("Type", "Unknown")
                if "Priority Score" in cve_details:
                    score = cve_details["Priority Score"].get("Score", 0)
                    grouped.setdefault(cve_type, []).append((score, cve_id))
    
    # For each type, sort by score and print the top 3 entries
    print(f"Top {amount} CVEs by Type (ID, Score, Type):")
    print("=" * 40)
    for cve_type, items in grouped.items():
        sorted_items = sorted(items, key=lambda x: x[0], reverse=True)
        print(f"Type: {cve_type}")
        print(f"Top {amount} CVEs:")
        for score, cve_id in sorted_items[:amount]:
            print(f"    CVE ID: {cve_id} | Score: {score} | Type: {cve_type}")
        print("-" * 40)


def list_best_by_category(file):
    """
    For each unique Category, find the CVE with the highest Priority Score and print all its details.
    """
    data = fh.read_json_file(file)
    best_by_category = {}  # Maps each Category to a tuple: (score, cve_id, details)

    # Iterate over all CVEs in the data
    for year in data:
        if not is_year_in_timeframe(year):
            continue
        for month in data[year]:
            for cve_id, cve_details in data[year][month].items():
                # Get the Category field; default to "Unknown" if missing.
                category = cve_details.get("Category", "Unknown")
                if "Priority Score" in cve_details:
                    score = cve_details["Priority Score"].get("Score", 0)
                    # Update if this category hasn't been seen or this CVE has a higher score.
                    if category not in best_by_category or score > best_by_category[category][0]:
                        best_by_category[category] = (score, cve_id, cve_details)
    
    # Print the best CVE for each category
    print("Best CVE per Category (All Details):")
    print("=" * 40)
    for category, (score, cve_id, details) in best_by_category.items():
        print(f"Category: {category}")
        print(f"CVE ID: {cve_id}")
        print(f"Priority Score: {score}")
        print("Details:")
        print(json.dumps(details, indent=4, sort_keys=False))
        print("-" * 40)


def list_top_amount_by_category(file, amount):
    """
    For each unique Category that has at least 5 CVEs, group the CVEs and print the top 10 based on Priority Score.
    Only the CVE ID and Priority Score are displayed for brevity.
    """
    data = fh.read_json_file(file)
    grouped = {}  # Maps each category to a list of tuples: (score, cve_id, details)

    # Group CVEs by category
    for year in data:
        if not is_year_in_timeframe(year):
            continue
        for month in data[year]:
            for cve_id, cve_details in data[year][month].items():
                # Use the "Category" field; default to "Unknown" if missing.
                category = cve_details.get("Category", "Unknown")
                if "Priority Score" in cve_details:
                    score = cve_details["Priority Score"].get("Score", 0)
                    grouped.setdefault(category, []).append((score, cve_id, cve_details))
    
    # For each category with at least 5 CVEs, sort the CVEs by score in descending order and print the top 10
    print(f"Top {amount} CVEs by Category (only categories with at least 5 CVEs):")
    print("=" * 40)
    for category, cve_list in grouped.items():
        if len(cve_list) < 5:
            continue  # Exclude categories with less than 5 CVEs
        sorted_cves = sorted(cve_list, key=lambda x: x[0], reverse=True)
        print(f"Category: {category} (Total CVEs: {len(cve_list)})")
        print(f"Top {amount} CVEs:")
        for score, cve_id, details in sorted_cves[:amount]:
            print(f"    CVE ID: {cve_id} | Priority Score: {score}")
        print("-" * 40)

# Example usage:
# list_top_10_by_category("enriched_data.json")
def list_top_amount_by_nr_poc2(file, amount, details=False):
    """
    For each unique Category that has at least 5 CVEs, group the CVEs and print the top 10 based on Priority Score.
    Only the CVE ID and Priority Score are displayed for brevity.
    """
    data = fh.read_json_file(file)
    grouped = {}  # Maps each category to a list of tuples: (score, cve_id, details)

    # Group CVEs by category
    for year in data:
        if not is_year_in_timeframe(year):
            continue
        for month in data[year]:
            for cve_id, cve_details in data[year][month].items():
                # Use the "Category" field; default to "Unknown" if missing.
                if "Priority Score" in cve_details:
                    score = cve_details["Priority Score"].get("Score", 0)
                    if details:
                        pocs = cve_details.get("PoC_Links", [])
                    else:
                        pocs = len(cve_details.get("PoC_Links", []))
                        grouped.setdefault(pocs, []).append((score, cve_id, cve_details))
    
    # For each category with at least 5 CVEs, sort the CVEs by score in descending order and print the top 10
    print(f"Top {amount} CVEs by Category (only categories with at least 5 CVEs):")
    print("=" * 40)
    for category, cve_list in grouped.items():
        if len(cve_list) < 5:
            continue  # Exclude categories with less than 5 CVEs
        sorted_cves = sorted(cve_list, key=lambda x: x[0], reverse=True)
        print(f"Category: {category} (Total CVEs: {len(cve_list)})")
        print(f"Top {amount} CVEs:")
        for score, cve_id, details in sorted_cves[:amount]:
            print(f"    CVE ID: {cve_id} | Priority Score: {score}")
        print("-" * 40)


def list_top_amount_by_nr_poc(file, amount, details=False):
    data = fh.read_json_file(file)
    scores_list = []

    for year in data:
        if not is_year_in_timeframe(year):
            continue
        for month in data[year]:
            for cve_id, cve_details in data[year][month].items():
                if "Priority Score" in cve_details:
                    score = cve_details["Priority Score"].get("Score", 0)
                    # pocs is already the count of PoC links (an integer)
                    pocs = len(cve_details.get("PoC_Links", []))
                    scores_list.append((cve_id, score, pocs, cve_details))
    
    sorted_scores = sorted(scores_list, key=lambda x: x[2], reverse=True)
    
    if details:
        top_amount = sorted_scores[:amount]
        for cve_id, score, pocs, cve_detail in top_amount:
            print(f"CVE ID: {cve_id}")
            print(f"Priority Score: {score}")
            # Print pocs directly, since it is already an integer.
            print(f"Nr of PoCs: {pocs}")
            print("Details:")
            print(json.dumps(cve_detail, indent=4, sort_keys=False))
            print("-" * 40)
    else:
        print("\n")
        print("-"*60)
        print("CVE ID\tPriority Score\tNr of PoCs")
        print("-"*60)
        for cve, score, pocs, _ in sorted_scores[:amount]:
            print(f"{cve}\t{score}\t{pocs}")
        print("-"*60)