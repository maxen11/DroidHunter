
--------------------------------------------------------------------------------

                        ==:                        =*
                         ++.                      #+
                          -*=     .-=====-.      ++
                           ==%%+-:::::::::::-*@#+#
                          =#=:::::::::::::::::::+%:
                        *=:::::::::::::::::::::::::+=
                      #=:::::::::::::::::::::::::::::#:
                    .#::::::::-+@%+::::::::::::::-**::=+
                   :+:::::::::-%@@@@%+:::::::-+#+-@@*::=*
                   *::::::::::=@@@.  @%:::::-%@@- #@#:::=%
                  %::::::::::::#@@@@@@=::::::+@@%#%@%%%%@%%@@%%%**%%%@=
                 -+:::::::::::::-*##*-:::::::#%###%%#@%%%#%%#@###@#::@%
                 **-:::::::::::::::::::::::::=@@@@@@@@@@@@@@@@@@@@@@@@
                    :*%@%*+=-----:::::::::::--=####@@@@****%@@#
               +*=-+#@***##%%%%%%%%%%%%%%%%%#%@%@@%%##%##%%%%%%%@%%%%%%%%@@:        .-@@%####@@@#
              @-::::::#*::::::::::::::::::-#@%###%######################%%##########%@@@%####@@@@
              @::::::::+@@%%%%%%%%%%%%%@@@%#####%############@%%@##@%####@@@@.        #%%%%%%%%#.
              -*:::::::::*@@@@@@@@@@@@%#*++*#@%%%%%%%%%%%%%%%@+%===*@@@@%++=
                %-::::::::-#@@@@#+=-:::::::::-@@@@@%@%@%@@@-%@=+::::-==%=
                #%%-::::::::::::::::::::::::::%@@%@@@%%%@@@@*::::::::-#.
               -*=+%*::::::::::::::::::::::::=@####@@%%%%@@=:::::::-#:
               +=-==*@*:::::::::::::::::-+#%%*+===+@%%#%#@@+:::::-#:
               #-::===*%=::::::::-+#@@%#+=========+%%%@@@#+::::-%=
               #::::-==+#%###%%##*+========---====+*# .*:::::-*-
               #::::::-==============-:::::::::===+*-   :%%%%:
              -+:::::::::-===--::::::::::::::::===+#
              +=:::::::::::::::::::::::::::::::==++#
              ++:::::::::::::::::::::::::::::::-=+*%-
               #::::::::::::::::::::::::::::::::::#*:=#
                *-:::::::::::::::::::::::::::::::*%=:::+-
                 #*::::::::::::::::::::::::::::+%*==::::*=
                *=:::::::::::::::::::::::::=#@@+===-:::::%
              :#-::::::::*=   .:-=====--.      :#=:::::::-+
             #=::::::::=#                       .*::::::::+:
            #-::::::::*-                         ++:::::::-#
           :+:::::::-%                            %=:::::::*
            #-:::::*-                              #-:::::-#
             +%**%#                                 #+::-**

--------------------------------------------------------------------------------

            ___  ____ ____ _ ___  _  _ _  _ _  _ ___ ____ ____
            |  \ |__/ |  | | |  \ |__| |  | |\ |  |  |___ |__/
            |__/ |  \ |__| | |__/ |  | |__| | \|  |  |___ |  \

--------------------------------------------------------------------------------
By: @maxen11
-------------------------------------------------------------------------------

---

## Overview

**DroidHunter** is a powerful command-line tool built in Python that helps security researchers, developers, and vulnerability analysts stay on top of the latest Android CVEs (Common Vulnerabilities and Exposures).

It automates the process of collecting, enriching, and analyzing security bulletin data from Android and CVE databases — giving you a streamlined way to prioritize and investigate security issues affecting Android devices.

---

## Why Use DroidHunter?

- **Track Vulnerabilities:** Monitor Android CVEs as soon as they're published.
- **Automated Enrichment:** Fetch detailed data from the NVD (National Vulnerability Database) and Proof-of-Concept (PoC) exploits from GitHub and ExploitDB.
- **Smart Scoring:** Automatically calculate priority scores based on severity, exploitability, and public PoCs.
- **File-Based:** Work with local JSON files and dig into the data offline or programmatically.
- **Insightful Exploration:** Search, filter, and prioritize CVEs by category, type, or PoC count with interactive menus.

---

## Features

- Fetch Android Security Bulletin CVEs
- Enrich data with CVSS scores from the NVD
- Gather PoC links from GitHub and ExploitDB
- Calculate custom priority scores
- List and explore top CVEs by different metrics
- Lookup CVE details and PoC links on demand
- Fully interactive terminal interface

---

## Getting Started

### Prerequisites

- Python 3.7+
- Internet connection (for enrichment steps)
- `requests`, `beautifulsoup4`, and other standard libraries (install via `requirements.txt` if available)

---

### Running the Tool

```bash
python3 DroidHunter.py
```
## DroidHunter Main Menu
  1. Collect Data from Android Security Bulletin
  2. Enrich with NVD data
  3. Enrich with PoCs
  4. Enrich and Calculate Scores
  5. List Scores
  6. Lookup CVE Details
  7. Lookup CVE PoC
  8. Remove Data Files
  9. Help
  10. Exit

When listing scores, you’ll be prompted to pick from available files like:

  1. asb-data.json
  2. enriched.json
  3. scored.json
  4. poc.json
  5. Exit

From there, you can choose:

  - Top CVEs by score
  - Full CVE details
  - CVEs by type or category
  - Most exploited (PoCs)
  - Timeframe filtering
  - CVE-specific lookups

## DroidHunter Scoring Profiles

DroidHunter supports multiple **scoring profiles** to help prioritize Android vulnerabilities based on the user's role or specific goals. These profiles affect how CVEs are scored during **Step 4: Enrich and Calculate Scores**.

---

## How It Works

When you select:
Main Menu → 4. Enrich and Calculate Scores

You’ll be asked to:
1. **Choose an enriched file**
2. **Select a scoring profile**

Options:
  1. researcher
  2. redteam
  3. blueteam
  4. default
  5. custom
  6. Exit

Choosing a profile determines how the following metrics are weighted:

| Code | Metric              | Description                                        |
|------|---------------------|----------------------------------------------------|
| Sr   | **Recency**         | Prioritizes recently published CVEs               |
| Ss   | **Severity**        | CVSS base score normalized (0–10 → 0–1)           |
| Se   | **Exploitability**  | Likelihood of successful exploitation             |
| Sp   | **PoC Availability**| Number of public proof-of-concept exploits        |
| Sv   | **Affected Versions** | Number of Android versions affected             |

---

## Available Profiles

### 1. `researcher`

> Focuses on **new** and **high-severity** vulnerabilities for academic/security research.

```
Sr = 2.5, Ss = 2.0, Se = 1.0, Sp = 0.5, Sv = 1.0
```
### 2. `redteam`
Targets CVEs that are easily exploitable and have public PoCs.
```
Sr = 1.0, Ss = 0.5, Se = 3.0, Sp = 3.0, Sv = 0.5
```
### 3. `blueteam`
Focuses on vulnerabilities that impact many versions and pose broader risk.
```
Sr = 2.0, Ss = 1.5, Se = 1.5, Sp = 1.0, Sv = 2.0
```

### 4. `default`
Balanced scoring profile for general triage or reporting.
```
Sr = 2.1, Ss = 0.6, Se = 2.1, Sp = 2.1, Sv = 1.2
```

### 5. `custom`
Allows you to define your own weights interactively.

You’ll be prompted for each weight:
  - Enter weight for Sr (0-5): 1.5
  - Enter weight for Ss (0-5): 2
  - Enter weight for Se  (0-5): 5
  - Enter weight for Sp  (0-5): 5
  - Enter weight for Sv (0-5): 1


> **Note:** On first run, the tool will download vulnerability databases from sources such as the NVD, ExploitDB, and a curated list of PoC repositories on GitHub. This setup process may take a few minutes and will consume disk space depending on the size of the datasets.

