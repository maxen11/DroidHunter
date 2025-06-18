import utils.file_handler as fh
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
    #print("ABRAKADABRA RESULTS \n\n\n")
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
    For each CVE type, group the CVEs and:
      1) Print the total count for that type
      2) Print the top `amount` CVEs by Priority Score (ID and score)
    """
    data = fh.read_json_file(file)
    grouped = {}  # Maps each type to a list of tuples: (score, cve_id)

    # Group CVEs by type
    for year, months in data.items():
        if not is_year_in_timeframe(year):
            continue
        for month in months:
            for cve_id, cve_details in data[year][month].items():
                cve_type = cve_details.get("Type", "Unknown")
                if "Priority Score" in cve_details:
                    score = cve_details["Priority Score"].get("Score", 0)
                    grouped.setdefault(cve_type, []).append((score, cve_id))

    # 1) Totals summary
    print("=== Total CVEs per Type ===")
    for cve_type, items in grouped.items():
        print(f"{cve_type}: {len(items)}")
    print()

    # 2) Top N by type
    print(f"=== Top {amount} CVEs per Type by Priority Score ===")
    for cve_type, items in grouped.items():
        # sort descending by score
        top_items = sorted(items, key=lambda x: x[0], reverse=True)[:amount]
        print(f"{cve_type} (Total: {len(items)})")
        for score, cve_id in top_items:
            print(f"  • {cve_id} — Score: {score}")
        print()



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

def count_cve_types_with_poc(file):
    """
    Count how many CVEs of each type have at least one attributed PoC.
    Only the existence of PoC_Links is checked, not their number.
    """
    data = fh.read_json_file(file)
    type_poc_count = {}  # type -> number of CVEs with at least one PoC

    for year in data:
        if not is_year_in_timeframe(year):
            continue
        for month in data[year]:
            for cve_id, cve_details in data[year][month].items():
                cve_type = cve_details.get("Type", "Unknown")
                pocs = cve_details.get("PoC_Links", [])
                if pocs:  # non-empty list means at least one PoC exists
                    type_poc_count[cve_type] = type_poc_count.get(cve_type, 0) + 1

    print("=== Number of CVEs with PoC per Type ===")
    for cve_type, count in sorted(type_poc_count.items(), key=lambda x: x[1], reverse=True):
        print(f"{cve_type}: {count}")

import re
import math
from collections import defaultdict, Counter
from statistics import mean, median, quantiles

# ————————————————————————————————————————————
# Helpers (place at module top)
# ————————————————————————————————————————————

CATEGORY_MAP = {
    'media frameworks':    'Media Framework',
    'frameworks':          'Framework',
    'libraries':           'Library',
    'system ui':           'System UI',
    'system server':       'System Server',
    'kernel components':   'Kernel Component',
}

def normalize_category(cat: str) -> str:
    """Clean up and unify Category strings."""
    if not cat or not cat.strip():
        return "Unknown"
    s = re.sub(r'\s+', ' ', cat).strip()
    s = re.sub(r'(?i)\bvulnerabilit(?:y|ies)\s*(?:in)?\b', '', s).strip()
    low = s.lower()
    return CATEGORY_MAP.get(low, s.title())

VULN_RE = re.compile(r'^(?P<vuln>.+?)\s+in\s+(?P<comp>.+)$', re.IGNORECASE)

def parse_category(cat_norm: str):
    """Split “Type in Component”; else bucket under Other."""
    m = VULN_RE.match(cat_norm)
    if m:
        return m.group('vuln').title(), m.group('comp').title()
    return "Other", cat_norm

SEV_MAP = {"Critical":4, "High":3, "Moderate":2, "Low":1}

def pearson(xs, ys):
    mx, my = mean(xs), mean(ys)
    num = sum((x-mx)*(y-my) for x,y in zip(xs,ys))
    den = math.sqrt(sum((x-mx)**2 for x in xs) * sum((y-my)**2 for y in ys))
    return num/den if den else 0

# ————————————————————————————————————————————
# The mega-stats function
# ————————————————————————————————————————————

def compute_all_cve_stats(file):
    data = fh.read_json_file(file)
    records = []

    # 1) Flatten & enrich every CVE into a record
    for year, months in data.items():
        if not is_year_in_timeframe(year):
            continue
        for month, cves in months.items():
            ym = f"{year}-{int(month):02d}"
            for cve_id, details in cves.items():
                # Category
                raw_cat  = details.get("Category","")
                cat_norm = normalize_category(raw_cat)
                vuln_t, comp = parse_category(cat_norm)

                # PoC
                raw_links = details.get("PoC_Links", [])
                links     = raw_links if isinstance(raw_links, list) else []
                num_poc   = len(links)
                has_poc   = 1 if num_poc>0 else 0
                stars     = [p.get("stars",0) for p in links if isinstance(p, dict)]
                avg_stars = mean(stars) if stars else 0
                max_stars = max(stars)  if stars else 0

                # References
                refs     = details.get("References","")
                num_refs = len([l for l in refs.splitlines() if l.strip()])

                # CVSS / NVD
                nvd   = (details.get("NVD_Data",{})
                                  .get("impact",{})
                                  .get("baseMetricV3",{}) or {})
                cvss  = nvd.get("cvssV3",{}) or {}
                bs    = cvss.get("baseScore")
                ex    = nvd.get("exploitabilityScore")
                im    = nvd.get("impactScore")
                ps    = details.get("Priority Score",{}).get("Score")

                # Severity
                sev     = details.get("Severity","Unknown")
                sev_num = SEV_MAP.get(sev)

                # Age in months (to May 2025)
                age_months = (2025 - int(year))*12 + (5 - int(month))

                records.append({
                    "year": int(year),
                    "month": int(month),
                    "year_month": ym,
                    "cve_id": cve_id,
                    "type": details.get("Type","Unknown"),
                    "severity": sev,
                    "severity_num": sev_num,
                    "category": cat_norm,
                    "vuln_type": vuln_t,
                    "component": comp,
                    "baseScore": bs,
                    "exploitabilityScore": ex,
                    "impactScore": im,
                    "priorityScore": ps,
                    "has_poc": has_poc,
                    "num_poc": num_poc,
                    "avg_poc_stars": avg_stars,
                    "max_poc_stars": max_stars,
                    "num_refs": num_refs,
                    "age_months": age_months
                })

    # 2) Grouping helper
    def group_by(field):
        d = defaultdict(list)
        for r in records: d[r[field]].append(r)
        return d

    by_year       = group_by("year")
    by_ym         = group_by("year_month")
    by_sev        = group_by("severity")
    by_type       = group_by("type")
    by_vuln_type  = group_by("vuln_type")
    by_comp       = group_by("component")

    # 3) Totals & time-series
    print(f"Total CVEs: {len(records)}")

    print("\n-- CVEs per Year --")
    for y, recs in sorted(by_year.items()):
        print(f"  {y}: {len(recs)}")

    print("\n-- CVEs per Month --")
    for ym, recs in sorted(by_ym.items()):
        print(f"  {ym}: {len(recs)}")

    # 4) Severity over time
    print("\n-- Avg Severity (numeric) by Month --")
    for ym, recs in sorted(by_ym.items()):
        vals = [r["severity_num"] for r in recs if r["severity_num"] is not None]
        if vals:
            print(f"  {ym}: {mean(vals):.2f}")

    print("\n-- Severity Counts by Month --")
    for ym, recs in sorted(by_ym.items()):
        cnt = Counter(r["severity"] for r in recs)
        parts = ", ".join(f"{s}:{c}" for s,c in cnt.items())
        print(f"  {ym}: {parts}")

    # 5) Severity distribution overall
    print("\n-- Severity Distribution --")
    for s, recs in sorted(by_sev.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"  {s}: {len(recs)}")

    # 6) Counts by type, vuln_type, component
    def print_counts(group, title):
        print(f"\n-- Counts by {title} --")
        for k, recs in sorted(group.items(), key=lambda x: len(x[1]), reverse=True):
            print(f"  {k}: {len(recs)}")

    print_counts(by_type,      "CVE Type")
    print_counts(by_vuln_type, "Vulnerability Type")
    print_counts(by_comp,      "Component")

    # 7) Missing-data
    missing_nvd = sum(1 for r in records if r["baseScore"] is None or r["exploitabilityScore"] is None or r["impactScore"] is None)
    missing_ps  = sum(1 for r in records if r["priorityScore"] is None)
    print(f"\nMissing NVD data: {missing_nvd}/{len(records)}")
    print(f"Missing Priority Score: {missing_ps}/{len(records)}")

    # 8) Score distributions & quartiles
    def score_summary(field):
        vals = [r[field] for r in records if r[field] is not None]
        if not vals: return
        mn, md, q1, q3 = mean(vals), median(vals), *quantiles(vals, n=4)[0::2]
        print(f"\n{field}: mean={mn:.2f}, median={md:.2f}, 25%={q1:.2f}, 75%={q3:.2f}")

    for fld in ("baseScore","exploitabilityScore","impactScore","priorityScore"):
        score_summary(fld)

    # 9) PoC & Reference link stats
    poc_counts = [r["num_poc"] for r in records]
    print(f"\nAvg #PoCs per CVE: {mean(poc_counts):.2f}")
    print(f"Max PoC stars overall: {max(r['max_poc_stars'] for r in records)}")
    print(f"Avg #References per CVE: {mean(r['num_refs'] for r in records):.2f}")

    # 10) PoC coverage by vuln_type & component
    def coverage(group, name):
        print(f"\n-- PoC Coverage by {name} (has/total, %) --")
        for k, recs in sorted(group.items(), key=lambda x: len(x[1]), reverse=True):
            has = sum(r["has_poc"] for r in recs)
            tot = len(recs)
            pct = has/tot*100 if tot else 0
            print(f"  {k}: {has}/{tot} ({pct:.1f}%)")

    coverage(by_vuln_type, "Vulnerability Type")
    coverage(by_comp,      "Component")

    # 11) Total PoCs per year & month
    print("\n-- Total PoCs per Year --")
    for y, recs in sorted(by_year.items()):
        print(f"  {y}: {sum(r['num_poc'] for r in recs)}")

    print("\n-- Total PoCs per Month --")
    for ym, recs in sorted(by_ym.items()):
        print(f"  {ym}: {sum(r['num_poc'] for r in recs)}")

    # 12) Top-5 lists
    def top_n(field, n=5):
        print(f"\n-- Top {n} CVEs by {field} --")
        for r in sorted(records, key=lambda x: x.get(field) or 0, reverse=True)[:n]:
            print(f"  {r['cve_id']} ({field}={r[field]})")

    top_n("num_poc")
    top_n("max_poc_stars")
    top_n("baseScore")
    top_n("exploitabilityScore")

    # 13) RQ1: CVSS WITH vs WITHOUT PoC
    for fld in ("baseScore","exploitabilityScore"):
        with_poc = [r[fld] for r in records if r["has_poc"] and r[fld] is not None]
        wo_poc   = [r[fld] for r in records if not r["has_poc"] and r[fld] is not None]
        if with_poc and wo_poc:
            print(f"\nAvg {fld} WITH PoC: {mean(with_poc):.2f}, WITHOUT PoC: {mean(wo_poc):.2f}")

    # 14) RQ2: Correlations CVSS vs #PoC
    bs_vals  = [r["baseScore"] for r in records if r["baseScore"] is not None]
    ex_vals  = [r["exploitabilityScore"] for r in records if r["exploitabilityScore"] is not None]
    poc_vals = [r["num_poc"] for r in records][:len(bs_vals)]
    if bs_vals:
        print(f"\nPearson(baseScore, #PoC): {pearson(bs_vals, poc_vals):.2f}")
    if ex_vals:
        print(f"Pearson(exploitabilityScore, #PoC): {pearson(ex_vals, poc_vals):.2f}")

    # 15) RQ2: Divergence by vulnerability type
    print("\n-- Avg(baseScore – exploitabilityScore) by Vulnerability Type --")
    for vt, recs in sorted(by_vuln_type.items(), key=lambda x: len(x[1]), reverse=True):
        diffs = [r["baseScore"]-r["exploitabilityScore"]
                 for r in recs
                 if r["baseScore"] is not None and r["exploitabilityScore"] is not None]
        if diffs:
            print(f"  {vt}: {mean(diffs):.2f}")

    # 16) RQ3: Correlations severity, refs & age
    sev_nums = [r["severity_num"] for r in records if r["severity_num"] is not None]
    poc_flag = [r["has_poc"]     for r in records if r["severity_num"] is not None]
    if sev_nums:
        print(f"\nPearson(severity_num, has_PoC): {pearson(sev_nums, poc_flag):.2f}")
    ref_vals = [r["num_refs"] for r in records]
    poc_vals = [r["num_poc"]  for r in records]
    print(f"Pearson(#refs, #PoC): {pearson(ref_vals, poc_vals):.2f}")

    ages     = [r["age_months"] for r in records]
    poc_mask = [r["has_poc"]    for r in records]
    print(f"Pearson(age_months, has_PoC): {pearson(ages, poc_mask):.2f}")

import json
import re
import math
from collections import Counter, defaultdict
from statistics import mean
import pandas as pd
import matplotlib.pyplot as plt
import networkx as nx

# assumes fh.read_json_file and is_year_in_timeframe(year) are available

# ————————————————————————————————————————————
# Helpers to group raw Category → broad component → layer
# ————————————————————————————————————————————
# ———————————————————————————————————————————————
# 1) CATEGORY_MAP: raw category → normalized category
# ———————————————————————————————————————————————
# ———————————————————————————————————————————————
# 1) CATEGORY_MAP: raw → normalized
# ———————————————————————————————————————————————
CATEGORY_MAP = {
    # Firmware / vendor blobs
    'broadcom components':               'Broadcom',
    'imagination technologies':          'Imagination',
    'imgtk components':                  'Imagination',
    'amlogic components':                'AMLogic',
    'amlogic':                           'AMLogic',
    'arm components':                    'Arm',
    'arm':                               'Arm',
    'mediatek components':               'MediaTek',
    'mediatek':                          'MediaTek',
    'nvidia components':                 'Nvidia',
    'unisoc components':                 'Unisoc',
    'unisoc':                            'Unisoc',
    'htc components':                    'HTC',
    'lg components':                     'LG',
    'fpc components':                    'FPC',
    'synaptics components':              'Synaptics',
    'misc oem':                          'Misc OEM',
    'multiple components':               'Multiple Components',
    'qualcomm closed-source components': 'Qualcomm',
    'qualcomm closed-source components 2014-2016 cumulative update': 'Qualcomm',
    'qualcomm components':               'Qualcomm',
    'bluetooth':        'Bluetooth',

    # Kernel core
    'kernel':                            'Kernel',
    'kernel lts':                        'Kernel',
    'kernel component':                  'Kernel',
    'kernel components':                 'Kernel',

    # Framework & runtime
    'framework':                         'Android Framework',
    'frameworks':                        'Android Framework',
    'framework apis':                    'Android Framework',
    'android framework':                 'Android Framework',
    'android runtime':                   'Android Runtime',
    'runtime':                           'Android Runtime',
    'library':                           'Library',
    'libraries':                         'Library',
    'media framework':                   'Media Framework',
    'media frameworks':                  'Media Framework',
    'widevine drm':         'Widevine',
    'widevine':             'Widevine', 

    # System-level
    'system':                            'System',
    'system ui':                         'System UI',
    'google play system updates':        'System',
    'google play system   updates':      'System',
    'platform':                          'System',
    'android tv':                        'System',
    'telecommunication':                 'System',
}

# ———————————————————————————————————————————————
# 2) LAYER_MAP: normalized → one of four layers
# ———————————————————————————————————————————————
LAYER_MAP = {
    # 1) Firmware
    'Broadcom':               'Firmware',
    'Bluetooth':              'Firmware',
    'Imagination':            'Firmware',
    'AMLogic':                'Firmware',
    'Arm':                    'Firmware',
    'MediaTek':               'Firmware',
    'Nvidia':                 'Firmware',
    'Unisoc':                 'Firmware',
    'HTC':                    'Firmware',
    'LG':                     'Firmware',
    'FPC':                    'Firmware',
    'Synaptics':              'Firmware',
    'Misc OEM':               'Firmware',
    'Multiple Components':    'Firmware',
    'Qualcomm':               'Firmware',

    # 2) Kernel
    'Kernel':                 'Kernel',

    # 3) Framework
    'Android Framework':      'Framework',
    'Android Runtime':        'Framework',
    'Library':                'Framework',
    'Media Framework':        'Framework',
     'Widevine': 'Firmware', 

    # 4) System
    'System':                 'System',
    'System UI':              'System',
    'Google Play System Updates': 'System',
    'Platform':               'System',
    'Android TV':             'System',
    'Telecommunication':      'System',
}



TYPE_MAP = {'eop': 'EoP'}  # normalize any variant of EOP→EoP

def _group_category(raw_cat: str) -> str:
    """Normalize raw Category string into a controlled set of buckets."""
    # 1) Handle None or blank up‐front
    if not raw_cat or not raw_cat.strip():
        return 'Unclassified'

    # 2) Collapse whitespace & lowercase
    key = re.sub(r'\s+', ' ', raw_cat.strip()).lower()

    # 3) Exact match first
    if key in CATEGORY_MAP:
        return CATEGORY_MAP[key]

    # 4) Substring match fallback
    for pattern, bucket in CATEGORY_MAP.items():
        if pattern and pattern in key:
            return bucket

    # 5) Give up
    return 'Other'

def _assign_layer(component: str) -> str:
    """Map normalized category into one of the system layers (or 'Other')."""
    return LAYER_MAP.get(component)



def _normalize_type(raw_type: str) -> str:
    if not raw_type or str(raw_type).strip().lower() in ('', 'none', 'nan', 'n/a'):
        return 'Unclassified'
    key = str(raw_type).strip().lower()
    return TYPE_MAP.get(key, str(raw_type).strip())

# bump all text sizes
plt.rcParams.update({'font.size': 14})

# ————————————————————————————————————————————
# Core loader: flatten JSON → DataFrame
# ————————————————————————————————————————————
def load_cve_dataframe(file: str) -> pd.DataFrame:
    """
    Reads year→month→CVE JSON via fh.read_json_file, filters by is_year_in_timeframe,
    and returns a DataFrame with columns:
      year_month, date, vuln_type, component, layer, baseScore.
    Missing or invalid Types → 'Unclassified'.
    """
    data = fh.read_json_file(file)
    records = []
    for year, months in data.items():
        if not is_year_in_timeframe(year):
            continue
        for month, cves in months.items():
            ym = f"{year}-{int(month):02d}"
            for cve_id, details in cves.items():
                # Type normalization + Unclassified fallback
                raw_type = details.get('Type')
                if not raw_type or str(raw_type).strip().lower() in ('', 'none', 'nan', 'n/a'):
                    vuln_type = "Unclassified"
                else:
                    vt_key = str(raw_type).strip().lower()
                    vuln_type = TYPE_MAP.get(vt_key, str(raw_type).strip())

                # Component & layer
                comp  = _group_category(details.get('Category',''))
                layer = _assign_layer(comp)

                # CVSS base score
                nvd   = (details.get('NVD_Data',{}) 
                             .get('impact',{}) 
                             .get('baseMetricV3',{}) or {})
                cvss  = nvd.get('cvssV3',{}) or {}
                bs    = cvss.get('baseScore')

                records.append({
                    'year_month': ym,
                    'date':       pd.to_datetime(ym),
                    'vuln_type':  vuln_type,
                    'component':  comp,
                    'layer':      layer,
                    'baseScore':  bs,
                })

    return pd.DataFrame(records)

# ————————————————————————————————————————————
# 1) Heatmap: avg CVSS baseScore by vuln_type vs layer
# ————————————————————————————————————————————
def plot_severity_heatmap(file: str):
    df = load_cve_dataframe(file)

    # build pivot WITHOUT fillna
    pivot = df.pivot_table(
        index='vuln_type',
        columns='layer',
        values='baseScore',
        aggfunc='mean'
    )

    print("\nAverage CVSS baseScore by Vulnerability Type vs Layer:\n")
    print(pivot)

    fig, ax = plt.subplots(figsize=(8,6))

    # mask the NaNs so they don’t get drawn as zero
    data = pivot.values
    mask = np.isnan(data)
    # create a colormap that shows masked entries in light gray
    cmap = plt.cm.viridis.copy()
    cmap.set_bad(color='lightgray')

    im = ax.imshow(
        np.ma.masked_where(mask, data), 
        aspect='auto',
        cmap=cmap,
        vmin=np.nanmin(data),
        vmax=np.nanmax(data)
    )

    # ticks
    ax.set_yticks(range(len(pivot.index)))
    ax.set_yticklabels(pivot.index, fontsize=16)
    ax.set_xticks(range(len(pivot.columns)))
    ax.set_xticklabels(pivot.columns, rotation=45, ha='right', fontsize=16)

    # colorbar
    cbar = fig.colorbar(im, ax=ax)
    cbar.set_label('Avg CVSS baseScore', fontsize=18)
    cbar.ax.tick_params(labelsize=14)

    ax.set_title('Heatmap: Avg CVSS baseScore by Type & Layer', fontsize=20)
    plt.tight_layout()
    plt.show()


# ————————————————————————————————————————————
# 2) Bipartite: vuln_type → layer
# ————————————————————————————————————————————
def plot_type_layer_bipartite(file: str):
    df = load_cve_dataframe(file)
    # keep Unclassified and all others
    edges = Counter(zip(df['vuln_type'], df['layer']))
    G = nx.DiGraph()
    for (vt, ly), w in edges.items():
        # vt and ly always strings like 'Unclassified'
        G.add_edge(vt, ly, weight=w)

    types  = sorted({vt for vt,_ in edges})
    layers = sorted({ly for _,ly in edges})
    pos = {t:(0,i) for i,t in enumerate(types)}
    pos.update({l:(1,i) for i,l in enumerate(layers)})

    plt.figure(figsize=(10,8))
    nx.draw_networkx_nodes(G, pos, nodelist=types, node_size=600, node_color='skyblue')
    nx.draw_networkx_nodes(G, pos, nodelist=layers, node_size=600, node_color='lightgreen')
    nx.draw_networkx_labels(G, pos, font_size=12)
    nx.draw_networkx_edges(
        G, pos,
        edgelist=G.edges(data=True),
        width=[d['weight']/10 for _,_,d in G.edges(data=True)],
        arrowstyle='-|>', arrowsize=8
    )
    plt.title('Vulnerability Type → System Layer', fontsize=20)
    plt.axis('off')
    plt.tight_layout()
    plt.show()

# ————————————————————————————————————————————
# 3) Boxplots: CVSS baseScore by vuln_type
# ————————————————————————————————————————————
def plot_cvss_boxplots(file: str, types_of_interest=None):
    """
    Draw one boxplot per vulnerability type in `types_of_interest`
    (default ['EoP','RCE','ID','DoS']) for CVSS base scores.
    Includes 'Unclassified' if present.
    """
    df = load_cve_dataframe(file)
    if types_of_interest is None:
        types_of_interest = ['EoP','RCE','ID','DoS','Unclassified']

    for t in types_of_interest:
        subset = df[df['vuln_type'] == t]['baseScore'].dropna()
        if subset.empty:
            continue
        plt.figure(figsize=(6,4))
        plt.boxplot(subset)
        plt.title(f'CVSS Base Score for {t}', fontsize=20)
        plt.ylabel('Base Score', fontsize=20)
        plt.xticks([1], [t], fontsize=20)
        plt.tight_layout()
        plt.show()


import json
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# assumes fh.read_json_file() and is_year_in_timeframe() are available,
# and load_cve_dataframe(file) from your module is already defined

def plot_layer_type_stacked_bar(file: str):
    """
    Stacked bar chart: CVE counts by System Layer & Vulnerability Type.
    """
    df = load_cve_dataframe(file)
    # group and pivot
    counts = df.groupby(['layer', 'vuln_type']).size().unstack(fill_value=0)
    
    # 1) Draw the plot and get the Axes
    fig, ax = plt.subplots(figsize=(10, 6))
    counts.plot(
        kind='bar',
        stacked=True,
        ax=ax,
       # colormap='tab20'  # optional: better color separation
    )

    # 2) Labels and title
    ax.set_xlabel('Layer', fontsize=20)
    ax.set_ylabel('CVE Count', fontsize=20)
    ax.set_title('CVE Counts per Layer & Vulnerability Type', fontsize=20)

    # 3) Rotate x‐tick labels 45° and bump font size
    ax.set_xticklabels(counts.index, rotation=45, ha='right', fontsize=20)
    ax.tick_params(axis='y', labelsize=20)

    ax.legend(title='Type', fontsize=20, title_fontsize=20)


    plt.tight_layout()
    plt.show()


def plot_cvss_violin_strip(file: str, types_of_interest=None):
    """
    Combined violin + strip plot of CVSS baseScore distributions
    for each vuln_type in types_of_interest.
    """
    import numpy as np
    import matplotlib.pyplot as plt

    df = load_cve_dataframe(file)
    if types_of_interest is None:
        types_of_interest = ['EoP', 'RCE', 'ID', 'DoS', 'Unclassified']

    data = [
        df[df['vuln_type'] == t]['baseScore'].dropna().values
        for t in types_of_interest
    ]
    positions = np.arange(len(types_of_interest))

    fig, ax = plt.subplots(figsize=(10, 6))
    # violin
    ax.violinplot(data, positions=positions, showmedians=True)

    # jittered strip
    for i, vals in enumerate(data):
        x = np.random.normal(i, 0.04, size=len(vals))
        ax.scatter(x, vals, s=10, alpha=0.3)

    ax.set_xticks(positions)
    ax.set_xticklabels(types_of_interest, fontsize=20, rotation=45)
    ax.set_ylabel('CVSS Base Score', fontsize=20)
    ax.set_title('CVSS Base Score Distribution by Vulnerability Type', fontsize=20)

    # set y-axis ticks at increments of 1 from 0 to 10
    ax.set_yticks(np.arange(2, 11, 1))
    ax.tick_params(axis='y', labelsize=18)

    plt.tight_layout()
    plt.show()



    # ————————————————————————————————————————————
# Extended loader: include PoC count
# ————————————————————————————————————————————
def load_extended_df(file: str) -> pd.DataFrame:
    """
    Flatten JSON → DataFrame with:
      year_month, date, vuln_type, component, baseScore, num_poc
    """
    data = fh.read_json_file(file)
    records = []
    for year, months in data.items():
        if not is_year_in_timeframe(year):
            continue
        for month, cves in months.items():
            ym = f"{year}-{int(month):02d}"
            for cve_id, d in cves.items():
                vuln_type = _normalize_type(d.get('Type'))
                comp      = _group_category(d.get('Category',''))
                # CVSS
                nvd  = (d.get('NVD_Data',{})
                            .get('impact',{})
                            .get('baseMetricV3',{}) or {})
                cvss = nvd.get('cvssV3',{}) or {}
                bs   = cvss.get('baseScore')
                # PoC count
                pocs = d.get('PoC_Links', [])
                num_poc = len(pocs) if isinstance(pocs, list) else 0

                layer = _assign_layer(comp)
                records.append({
                    'year_month': ym,
                    'date':        pd.to_datetime(ym),
                    'vuln_type':   vuln_type,
                    'component':   comp,
                    'layer':       layer,
                    'baseScore':   bs,
                    'num_poc':     num_poc,
                })
    return pd.DataFrame(records)


# ————————————————————————————————————————————
# 1) Density plot of CVSS by vulnerability type
# ————————————————————————————————————————————
def plot_cvss_density_by_type(file: str):
    df = load_extended_df(file)
    types = df['vuln_type'].unique()
    plt.figure(figsize=(10,6))
    for t in sorted(types):
        subset = df[df['vuln_type']==t]['baseScore'].dropna()
        if len(subset)>1:
            subset.plot(kind='kde', label=t)
    plt.xlabel('CVSS BaseScore', fontsize=20)
    plt.title('Density of CVSS BaseScore by Vulnerability Type', fontsize=20)
    plt.legend()
    plt.tight_layout()
    plt.show()

# ————————————————————————————————————————————
# 2) Density plot of CVSS by component
# ————————————————————————————————————————————
def plot_cvss_density_by_component(file: str):
    df = load_extended_df(file)
    comps = df['component'].value_counts().nlargest(8).index  # top 8 only
    plt.figure(figsize=(10,6))
    for c in comps:
        subset = df[df['component']==c]['baseScore'].dropna()
        if len(subset)>1:
            subset.plot(kind='kde', label=c)
    plt.xlabel('CVSS BaseScore', fontsize=20)
    plt.title('Density of CVSS BaseScore by Top Components', fontsize=20)
    plt.legend()
    plt.tight_layout()
    plt.show()

# ————————————————————————————————————————————
# 3) Bar chart: avg #PoCs by vulnerability type
# ————————————————————————————————————————————
def plot_avg_pocs_by_type(file: str):
    df = load_extended_df(file)
    avg = df.groupby('vuln_type')['num_poc'].mean().sort_values(ascending=False)

    # 1) Create fig/ax explicitly
    fig, ax = plt.subplots(figsize=(8,5))

    # 2) Draw the bar chart on that ax
    avg.plot(kind='bar', ax=ax, color='steelblue', edgecolor='k')

    # 3) Axis labels and title
    ax.set_xlabel('Vulnerability Type', fontsize=20)
    ax.set_ylabel('Avg # PoCs', fontsize=20)
    ax.set_title('Avg Nr of PoCs per CVE by Vulnerability Type',
                 fontsize=20)

    # 4) Rotate x‐tick labels and bump up font size
    ax.set_xticklabels(avg.index, rotation=45, ha='right', fontsize=16)
    ax.tick_params(axis='y', labelsize=16)

    plt.tight_layout()
    plt.show()


# ————————————————————————————————————————————
# 4) Bar chart: avg #PoCs by component
# ————————————————————————————————————————————
def plot_avg_pocs_by_component(file: str):
    df = load_extended_df(file)
    avg = df.groupby('component')['num_poc'].mean().sort_values(ascending=False).head(10)
    plt.figure(figsize=(8,5))
    avg.plot(kind='bar')
    plt.ylabel('Avg # PoCs', fontsize=20)
    plt.title('Average Number of PoCs per CVE by Component (top 10)', fontsize=20)
    plt.tight_layout()
    plt.show()

# ————————————————————————————————————————————
# 5) Correlation matrix heatmap
# ————————————————————————————————————————————
def plot_correlation_heatmap(file: str):
    df = load_extended_df(file)
    corr = df[['baseScore','num_poc']].corr()
    plt.figure(figsize=(5,4))
    im = plt.imshow(corr, vmin=-1, vmax=1, cmap='coolwarm')
    plt.xticks([0,1], corr.columns, rotation=45, fontsize=20)
    plt.yticks([0,1], corr.index, fontsize=20)
    plt.colorbar(im, fraction=0.046, pad=0.04)
    plt.title('Correlation Matrix', fontsize=20)
    plt.tight_layout()
    plt.show()

def plot_poc_coverage_timeseries_by_type(file: str, types_of_interest=None):
    """
    Time series of PoC coverage (%) over time, with one line per vulnerability type.
    PoC coverage is defined as the percent of CVEs of that type in each month
    that have at least one PoC.
    """
    # Load extended DataFrame (expects load_extended_df to exist)
    df = load_extended_df(file)
    # Compute has_poc flag
    df['has_poc'] = df['num_poc'] > 0

    # If no specific types given, use all observed types
    if types_of_interest is None:
        types_of_interest = sorted(df['vuln_type'].unique())

    # Group by month and type, compute coverage %
    coverage = (
        df[df['vuln_type'].isin(types_of_interest)]
        .groupby(['date', 'vuln_type'])['has_poc']
        .mean()
        .unstack(fill_value=0)  # fraction [0,1]
        * 100.0                   # to percentage
    )

    # Plot
    plt.figure(figsize=(10, 6))
    for t in types_of_interest:
        if t in coverage:
            plt.plot(
                coverage.index,
                coverage[t],
                marker='o',
                label=t
            )

    plt.xlabel('Date', fontsize=20)
    plt.ylabel('PoC Coverage (%)', fontsize=20)
    plt.title('Time Series: PoC Coverage by Vulnerability Type', fontsize=20)
    plt.legend(title='Vuln Type', fontsize=20, title_fontsize=20)
    plt.xticks(rotation=45, fontsize=20)
    plt.yticks(fontsize=20)
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.show()



import numpy as np

def plot_poc_cvss_coverage_by_type(file: str, types_of_interest=None, bin_width: float = 1.0):
    """
    For each vulnerability type, bin CVSS baseScore into intervals of width `bin_width`,
    compute the % of CVEs in each bin that have at least one PoC, and plot a line per type.
    """
    # load data
    df = load_extended_df(file)
    # mark PoC existence
    df['has_poc'] = df['num_poc'] > 0
    # drop missing scores
    df = df[df['baseScore'].notna()]
    # choose types
    all_types = sorted(df['vuln_type'].unique())
    if types_of_interest is None:
        types_of_interest = all_types
    # define bins
    max_score = df['baseScore'].max()
    bins = np.arange(0, max_score + bin_width, bin_width)
    # assign bins
    df['score_bin'] = pd.cut(df['baseScore'], bins=bins, include_lowest=True, right=False)
    # compute coverage: fraction of has_poc per (type, bin)
    coverage = (
        df[df['vuln_type'].isin(types_of_interest)]
        .groupby(['score_bin','vuln_type'])['has_poc']
        .mean()
        .unstack(level=1)
        .fillna(0) * 100.0
    )
    # compute bin midpoints for x-axis
    midpoints = [interval.left + bin_width/2 for interval in coverage.index]
    # plot
    plt.figure(figsize=(10, 6))
    for t in types_of_interest:
        if t in coverage:
            plt.plot(midpoints, coverage[t], marker='o', label=t)
    plt.xlabel('CVSS BaseScore', fontsize=20)
    plt.ylabel('PoC Coverage (%)', fontsize=20)
    plt.title('PoC Coverage vs. CVSS BaseScore by Vulnerability Type', fontsize=20)
    plt.xticks(midpoints, [f"{m:.1f}" for m in midpoints], rotation=45)
    plt.ylim(0, 100)
    plt.legend(title='Vuln Type', fontsize=20, title_fontsize=13)
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.show()


def plot_poc_cvss_coverage_by_half_point_bin(
    file: str,
    types_of_interest=None,
    bin_width: float = 0.5,
    min_count: int = 5
):
    """
    Plot PoC coverage (%) in fixed 0.5-point CVSS bins, for each vuln_type.
    Only bins with at least `min_count` CVEs (across all types) are shown.
    """
    import numpy as np
    import pandas as pd
    import matplotlib.pyplot as plt

    # Load data
    df = load_extended_df(file)
    df['has_poc'] = df['num_poc'] > 0
    df = df[df['baseScore'].notna()]

    # Determine bins from 0 to max score
    max_score = df['baseScore'].max()
    bins = np.arange(0, max_score + bin_width, bin_width)
    df['score_bin'] = pd.cut(df['baseScore'], bins=bins, right=False)

    # Filter bins with enough samples
    bin_counts = df.groupby('score_bin').size()
    valid_bins = bin_counts[bin_counts >= min_count].index

    # Restrict types if needed
    if types_of_interest is None:
        types_of_interest = sorted(df['vuln_type'].unique())

    # Compute coverage per (bin, type)
    cov = (
        df[df['score_bin'].isin(valid_bins) & df['vuln_type'].isin(types_of_interest)]
        .groupby(['score_bin','vuln_type'])['has_poc']
        .mean()
        .unstack(fill_value=0) * 100.0
    )

    # Compute bin midpoints for x-axis
    midpoints = [interval.left + bin_width/2 for interval in cov.index]

    # Plot
    plt.figure(figsize=(10,6))
    for t in types_of_interest:
        if t in cov:
            plt.plot(
                midpoints,
                cov[t],
                marker='o',
                label=t
            )

    plt.xlabel('CVSS BaseScore (binned, 0.5 increments)', fontsize=20)
    plt.ylabel('PoC Coverage (%)', fontsize=20)
    plt.title(
        f'PoC Coverage vs. CVSS (0.5‐point bins, ≥{min_count} CVEs/bin)',
        fontsize=20
    )
    plt.xticks(midpoints, [f"{m:.1f}" for m in midpoints], rotation=45)
    plt.ylim(0, 100)
    plt.legend(title='Vuln Type', fontsize=20, title_fontsize=20)
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.show()

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

def plot_poc_cvss_coverage_1point_bins(
    file: str,
    types_of_interest=None,
    min_count: int = 5
):
    """
    PoC coverage (%) in 1-point CVSS bins [0–1),[1–2),…,[9–10],
    with only bins that have at least `min_count` CVEs.
    """
    import numpy as np
    import pandas as pd
    import matplotlib.pyplot as plt

    # 1) load & prepare
    df = load_extended_df(file)
    df['has_poc'] = df['num_poc'] > 0
    df = df.dropna(subset=['baseScore'])

    # 2) create 1-point bins
    bin_width = 1.0
    edges = np.arange(0.0, 10.0 + bin_width, bin_width)  # [0,1,2,…,10]
    df['bin'] = pd.cut(df['baseScore'], bins=edges, right=False)

    # 3) select only bins with enough CVEs
    total_per_bin = df.groupby('bin').size()
    valid_bins = total_per_bin[total_per_bin >= min_count].index
    df = df[df['bin'].isin(valid_bins)]

    # 4) pick types
    all_types = sorted(df['vuln_type'].unique())
    if types_of_interest is None:
        types_of_interest = all_types

    # 5) compute coverage per (bin, type)
    cov = (
        df[df['vuln_type'].isin(types_of_interest)]
        .groupby(['bin','vuln_type'])['has_poc']
        .mean()
        .unstack(fill_value=0) * 100.0
    )

    # 6) compute midpoints from the filtered bins
    midpoints = [interval.left + bin_width/2 for interval in cov.index]

    # 7) plot
    plt.figure(figsize=(10,6))
    for t in types_of_interest:
        if t in cov:
            plt.plot(
                midpoints,
                cov[t],
                marker='o',
                label=t
            )

    plt.xlabel('CVSS BaseScore (binned)', fontsize=20)
    plt.ylabel('PoC Coverage (%)', fontsize=20)
    plt.title(
        f'PoC Coverage vs. CVSS (1-point bins, ≥{min_count} CVEs/bin)',
        fontsize=20
    )
    plt.xticks(midpoints, [f"{m:.1f}" for m in midpoints], rotation=45)
    plt.ylim(0,100)
    plt.legend(title='Vuln Type', fontsize=20, title_fontsize=13)
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.show()



def plot_poc_cvss_coverage_with_counts(
    file: str,
    types_of_interest=None,
    bin_width: float = 1.0,
    min_count: int = 1
):
    """
    Plot PoC coverage (%) per CVSS bin (default 1.0‐point bins) as a line,
    plus the total number of CVEs in each bin as a bar on a secondary y-axis.
    Only bins with at least `min_count` CVEs are shown.
    """
    import numpy as np
    import pandas as pd
    import matplotlib.pyplot as plt

    # 1) Load & prepare data
    df = load_extended_df(file)
    df['has_poc'] = df['num_poc'] > 0
    df = df.dropna(subset=['baseScore'])

    # 2) Define integer bins 0–10
    edges = np.arange(0.0, 10.0 + bin_width, bin_width)
    df['bin'] = pd.cut(df['baseScore'], bins=edges, right=False)

    # 3) Filter to bins with enough CVEs
    total_per_bin = df.groupby('bin').size()
    valid_bins = total_per_bin[total_per_bin >= min_count].index

    # 4) Choose types
    all_types = sorted(df['vuln_type'].unique())
    if types_of_interest is None:
        types_of_interest = all_types

    # 5) Compute coverage and counts
    subset = df[df['bin'].isin(valid_bins) & df['vuln_type'].isin(types_of_interest)]
    cov = subset.groupby(['bin','vuln_type'])['has_poc']\
                .mean().unstack(fill_value=0) * 100.0
    counts = df[df['bin'].isin(valid_bins)].groupby('bin').size()

    # 6) Compute x positions (midpoints)
    midpoints = [interval.left + bin_width/2 for interval in cov.index]

    # 7) Plot
    fig, ax1 = plt.subplots(figsize=(10, 6))

    # Line: PoC coverage
    for t in types_of_interest:
        if t in cov:
            ax1.plot(
                midpoints,
                cov[t],
                marker='o',
                label=f"{t} coverage"
            )
    ax1.set_xlabel('CVSS BaseScore (binned)', fontsize=20)
    ax1.set_ylabel('PoC Coverage (%)', fontsize=20)
    ax1.set_ylim(0, 100)
    ax1.tick_params(axis='x', labelsize=20)
    ax1.tick_params(axis='y', labelsize=20)

    # Secondary axis: counts as bars
    ax2 = ax1.twinx()
    ax2.bar(
        midpoints,
        counts.loc[cov.index],  # align bins
        width=bin_width*0.8,
        alpha=0.3,
        color='gray',
        label='CVE count'
    )
    ax2.set_ylabel('Number of CVEs in bin', fontsize=20)
    ax2.tick_params(axis='y', labelsize=20)

    # Legends
    lines, labels = ax1.get_legend_handles_labels()
    bars, bar_labels = ax2.get_legend_handles_labels()
    ax1.legend(lines + bars, labels + bar_labels, loc='upper left', fontsize=20, title_fontsize=20)

    plt.title(f"PoC Coverage and CVE Count per CVSS Bin (≥{min_count} CVEs)", fontsize=20)
    plt.xticks(midpoints, [f"{m:.1f}" for m in midpoints], rotation=45, fontsize=20)
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.show()



def plot_cve_count_by_score(
    file: str,
    bin_width: float = 1.0
):
    """
    Plot the total number of CVEs in each CVSS baseScore bin.
    Bins are [0–1),[1–2),…,[9–10]. This shows raw CVE volume per score.
    """
    import numpy as np
    import pandas as pd
    import matplotlib.pyplot as plt

    # 1) load & flatten
    df = load_extended_df(file)
    # drop missing scores
    df = df[df['baseScore'].notna()]

    # 2) define integer bins 0–10
    edges = np.arange(0.0, 10.0 + bin_width, bin_width)  # [0,1,2,…,10]
    df['bin'] = pd.cut(df['baseScore'], bins=edges, right=False)

    # 3) count CVEs per bin
    counts = df.groupby('bin').size()

    # 4) compute midpoints for plotting
    midpoints = [interval.left + bin_width/2 for interval in counts.index]

    # 5) bar plot
    plt.figure(figsize=(8,5))
    plt.bar(midpoints, counts.values, width=bin_width*0.8, color='skyblue', edgecolor='k')
    plt.xticks(midpoints, [f"{m:.1f}" for m in midpoints], fontsize=20)
    plt.xlabel('CVSS BaseScore (binned)', fontsize=20)
    plt.ylabel('Number of CVEs', fontsize=20)
    plt.title('CVE Count by CVSS BaseScore Bin', fontsize=20)
    plt.grid(axis='y', alpha=0.3)
    plt.tight_layout()
    plt.show()


def plot_poc_coverage_with_counts(
    file: str,
    types_of_interest=None,
    bin_width: float = 1.0,
    min_count: int = 5
):
    """
    Combined plot:
      - Line(s): PoC coverage (%) per CVSS bin by vuln type
      - Bars:  total CVE count per bin
    """
    import numpy as np
    import pandas as pd
    import matplotlib.pyplot as plt

    df = load_extended_df(file)
    df['has_poc'] = df['num_poc'] > 0
    df = df[df['baseScore'].notna()]

    # bins
    edges = np.arange(0.0, 10.0 + bin_width, bin_width)
    df['bin'] = pd.cut(df['baseScore'], bins=edges, right=False)

    # overall counts (bars)
    total_counts = df.groupby('bin').size()
    valid_bins = total_counts[total_counts >= min_count].index

    # types & coverage (lines)
    if types_of_interest is None:
        types_of_interest = sorted(df['vuln_type'].unique())
    cov = (
        df[df['bin'].isin(valid_bins)]
        .groupby(['bin','vuln_type'])['has_poc']
        .mean()
        .unstack(fill_value=0) * 100.0
    )

    # midpoints
    midpoints = [interval.left + bin_width/2 for interval in cov.index]

    # plot
    fig, ax1 = plt.subplots(figsize=(10,6))
    # bars
    ax1.bar(
        midpoints,
        total_counts.loc[cov.index],
        width=bin_width*0.8,
        alpha=0.3,
        color='gray',
        label='CVE count'
    )
    ax1.set_xlabel('CVSS BaseScore (binned)', fontsize=20)
    ax1.set_ylabel('Number of CVEs', fontsize=20)

    # lines
    ax2 = ax1.twinx()
    for t in types_of_interest:
        if t in cov:
            ax2.plot(
                midpoints,
                cov[t],
                marker='o',
                label=f"{t} coverage"
            )
    ax2.set_ylabel('PoC Coverage (%)', fontsize=20)
    ax2.set_ylim(0,100)

    # legends
    bars, bar_labels = ax1.get_legend_handles_labels()
    lines, line_labels = ax2.get_legend_handles_labels()
    ax1.legend(bars + lines, bar_labels + line_labels, loc='upper left')

    plt.title(f'CVE Counts & PoC Coverage per CVSS Bin (≥{min_count} CVEs)', fontsize=20)
    plt.xticks(midpoints, [f"{m:.1f}" for m in midpoints], rotation=45)
    plt.grid(axis='y', alpha=0.3)
    plt.tight_layout()
    plt.show()

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

def plot_cve_count_heatmap_by_type_score(
    file: str,
    types_of_interest=None,
    bin_width: float = 1.0
):
    """
    Heatmap: CVE count for each vulnerability type in each CVSS bin.
    Bins = [0–1),[1–2),…,[9–10]. Shows raw counts per (type, bin).
    """
    # 1) load data
    df = load_extended_df(file)
    df = df.dropna(subset=['baseScore'])

    # 2) define bins
    edges = np.arange(0.0, 10.0 + bin_width, bin_width)
    df['score_bin'] = pd.cut(df['baseScore'], bins=edges, right=False)

    # 3) filter types
    all_types = sorted(df['vuln_type'].unique())
    if types_of_interest is None:
        types_of_interest = all_types

    # 4) pivot counts
    pivot = (
        df[df['vuln_type'].isin(types_of_interest)]
        .groupby(['score_bin','vuln_type'])
        .size()
        .unstack(fill_value=0)
    )

    # 5) plot heatmap
    plt.figure(figsize=(10,6))
    im = plt.imshow(pivot.T, aspect='auto', cmap='Blues')
    plt.colorbar(im, label='CVE Count')
    # x axis = bins
    bins = [f"{interval.left:.0f}–{interval.left+bin_width:.0f}" for interval in pivot.index]
    plt.xticks(range(len(bins)), bins, rotation=45, ha='right')
    # y axis = types
    plt.yticks(range(len(pivot.columns)), pivot.columns)
    plt.xlabel('CVSS BaseScore Bin', fontsize=20)
    plt.ylabel('Vulnerability Type', fontsize=20)
    plt.title('CVE Counts by CVSS Bin & Vulnerability Type', fontsize=20)
    plt.tight_layout()
    plt.show()


def plot_cve_count_stacked_bar_by_score_type(
    file: str,
    types_of_interest=None,
    bin_width: float = 1.0
):
    """
    Stacked bar chart: for each CVSS bin, how many CVEs of each type.
    """
    import numpy as np
    import pandas as pd
    import matplotlib.pyplot as plt

    # 1) load & prepare
    df = load_extended_df(file)
    df = df.dropna(subset=['baseScore'])

    # 2) define bins
    edges = np.arange(0.0, 10.0 + bin_width, bin_width)
    df['score_bin'] = pd.cut(df['baseScore'], bins=edges, right=False)
    labels = [f"{int(i)}–{int(i+bin_width)}" for i in edges[:-1]]

    # 3) choose types
    all_types = sorted(df['vuln_type'].unique())
    if types_of_interest is None:
        types_of_interest = all_types

    # 4) pivot counts
    pivot = (
        df[df['vuln_type'].isin(types_of_interest)]
        .groupby(['score_bin', 'vuln_type'])
        .size()
        .unstack(fill_value=0)
    )
    pivot.index = labels[:len(pivot)]  # label bins

    # 5) plot
    ax = pivot.plot(
        kind='bar',
        stacked=True,
        figsize=(10, 6)
    )
    ax.set_xlabel('CVSS BaseScore Bin', fontsize=20)
    ax.set_ylabel('CVE Count', fontsize=20)
    ax.set_title('Stacked CVE Counts by CVSS Bin & Vulnerability Type', fontsize=20)

    ax.legend(title='Type', fontsize=20, title_fontsize=20)

    # Set y‐axis tick label size
    ax.tick_params(axis='y', labelsize=20)

    # Rotate + right‐align x‐tick labels:
    ax.tick_params(axis='x', labelsize=20)  # only setting labelsize via tick_params
    for lbl in ax.get_xticklabels():
        lbl.set_rotation(45)
        lbl.set_ha('right')

    plt.tight_layout()
    plt.show()



import pandas as pd
import matplotlib.pyplot as plt

def plot_poc_coverage_smoothed(file: str, window: int = 6):
    """
    Plot 6-month rolling average PoC coverage (%) for the four main types.
    """
    df = load_extended_df(file)
    df['has_poc'] = df['num_poc'] > 0

    # restrict to main types and to months with data
    types = ['EoP','RCE','ID','DoS']
    df = df[df['vuln_type'].isin(types)].dropna(subset=['date'])

    # group monthly coverage
    monthly = (
        df.groupby(['date','vuln_type'])['has_poc']
          .mean()
          .unstack()
          * 100
    ).resample('M').mean()  # ensure regular monthly index

    # smooth with rolling window
    smooth = monthly.rolling(window=window, min_periods=1).mean()

    # plot
    plt.figure(figsize=(10,5))
    ax = plt.gca()
    for t in types:
        ax.plot(smooth.index, smooth[t], label=t, linewidth=2)
        # endpoint marker
        ax.plot(smooth.index[-1:], smooth[t].iloc[-1:], 'o', markersize=8)

    # styling
    ax.set_title(f'6-Month Rolling PoC Coverage by Vulnerability Type', fontsize=20)
    ax.set_xlabel('Date', fontsize=20)
    ax.set_ylabel('PoC Coverage (%)', fontsize=20)
    ax.set_ylim(0,100)
    ax.xaxis.set_major_locator(plt.MaxNLocator(6))      # ~6 ticks
    ax.xaxis.set_major_formatter(plt.FixedFormatter(
        [d.strftime("%Y") for d in smooth.index[::len(smooth)//6 or 1]]
    ))
    ax.grid(True, alpha=0.3)
    ax.legend(title='Type', fontsize=20, title_fontsize=13, loc='upper left')
    plt.tight_layout()
    plt.show()


def plot_poc_coverage_small_multiples(file: str):
    """
    One subplot per vulnerability type (EoP, RCE, ID, DoS),
    showing raw monthly PoC coverage (%) as a line.
    """
    df = load_extended_df(file)
    df['has_poc'] = df['num_poc'] > 0
    types = ['EoP','RCE','ID','DoS']
    df = df[df['vuln_type'].isin(types)].dropna(subset=['date'])

    # compute monthly coverage
    monthly = (
        df.groupby(['date','vuln_type'])['has_poc']
          .mean()
          .unstack()
          * 100
    ).resample('M').mean()

    fig, axes = plt.subplots(2,2, figsize=(12,8), sharex=True, sharey=True)
    axes = axes.flatten()
    for ax, t in zip(axes, types):
        ax.plot(monthly.index, monthly[t], color='C0', linewidth=2)
        ax.set_title(t, fontsize=20)
        ax.grid(True, alpha=0.3)
        ax.set_ylim(0,100)
    fig.suptitle('Monthly PoC Coverage by Vulnerability Type', fontsize=20)
    for ax in axes[-2:]:
        ax.set_xlabel('Date', fontsize=20)
    for ax in axes[::2]:
        ax.set_ylabel('Coverage (%)', fontsize=20)
    plt.tight_layout(rect=[0,0,1,0.96])
    plt.show()


import matplotlib.pyplot as plt

def plot_poc_availability_by_type(file: str):
    """
    For each vulnerability type, compute how many CVEs have at least one PoC,
    and plot the raw counts annotated with percentage coverage.
    """
    # 1) Load your flattened DF (must provide num_poc, vuln_type)
    df = load_extended_df(file)
    df['has_poc'] = df['num_poc'] > 0

    # 2) Aggregate per type
    stats = df.groupby('vuln_type')['has_poc'] \
              .agg(total_cves='size', cves_with_poc='sum')
    stats['pct_with_poc'] = stats['cves_with_poc'] / stats['total_cves'] * 100

    # 3) Plot raw counts
    fig, ax = plt.subplots(figsize=(8, 5))
    bars = stats['cves_with_poc'].plot(kind='bar', ax=ax, color='steelblue')
    ax.set_xlabel('Vulnerability Type', fontsize=20)
    ax.set_ylabel('CVE Count (PoC ≥1)', fontsize=20)
    ax.set_title('PoC Availability by Vulnerability Type', fontsize=20)

    # 4) Add headroom
    max_count = stats['cves_with_poc'].max()
    ax.set_ylim(0, max_count * 1.2)

    # 5) Annotate each bar with both count and percentage
    for i, (vtype, row) in enumerate(stats.iterrows()):
        count = int(row['cves_with_poc'])
        pct   = row['pct_with_poc']
        # place text a bit above the bar top
        y = count + max_count * 0.02
        ax.text(i, y,
                f"{count}\n({pct:.1f}%)",
                ha='center', va='bottom', fontsize=16)

    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.show()


import json
from collections import defaultdict
import matplotlib.pyplot as plt

def plot_avg_pocs_by_layer(file: str):
    """
    Compute and plot the average number of PoCs per CVE for each system layer
    (Application, Framework, Kernel, Firmware, System, etc.).
    """
    # 1) Load your flattened DataFrame which must include 'layer' and 'num_poc'
    df = load_extended_df(file)

    # 2) Filter to valid layers and drop missing
    df = df.dropna(subset=['layer'])

    # 3) Compute average PoCs per CVE for each layer
    avg_pocs = df.groupby('layer')['num_poc'].mean().sort_values(ascending=False)

    # 4) Plot
    plt.figure(figsize=(10, 6))
    avg_pocs.plot(
        kind='bar',
        color='steelblue',
        edgecolor='k'
    )
    plt.xlabel('System Layer', fontsize=20)
    plt.ylabel('Average # of PoCs per CVE', fontsize=20)
    plt.title('Average Number of PoCs by System Layer', fontsize=20)
    plt.xticks(rotation=45, ha='right', fontsize=20)
    plt.yticks(fontsize=20)
    plt.tight_layout()
    plt.show()


def plot_cve_type_distribution(file: str):
    """
    Plot the distribution (counts) of CVE vulnerability types, 
    annotating each bar with its count and % of total.
    """
    # 1) Load DataFrame & count
    df = load_extended_df(file)
    type_counts = df['vuln_type'].value_counts().sort_values(ascending=False)
    total = type_counts.sum()

    # 2) Plot bars
    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(
        type_counts.index, 
        type_counts.values, 
        color='steelblue', 
        edgecolor='k'
    )

    # 3) Labels & title
    ax.set_xlabel('Vulnerability Type', fontsize=16)
    ax.set_ylabel('Number of CVEs', fontsize=16)
    ax.set_title('CVE Count by Vulnerability Type', fontsize=18)
    ax.set_xticklabels(type_counts.index, rotation=45, ha='right', fontsize=14)
    ax.tick_params(axis='y', labelsize=14)

    # 4) Add headroom so text fits
    max_count = type_counts.max()
    ax.set_ylim(0, max_count * 1.2)

    # 5) Annotate each bar
    for bar in bars:
        h   = bar.get_height()
        pct = h / total * 100
        y   = h + max_count * 0.02  # 2% of max_count above bar
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            y,
            f"{int(h)}\n({pct:.1f}%)",
            ha='center', va='bottom',
            fontsize=14
        )

    plt.tight_layout()
    plt.show()


