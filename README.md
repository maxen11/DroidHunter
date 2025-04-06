
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

> **Note:** On first run, the tool will download vulnerability databases from sources such as the NVD, ExploitDB, and a curated list of PoC repositories on GitHub. This setup process may take a few minutes and will consume disk space depending on the size of the datasets.

