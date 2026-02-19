# MITRE ATT&CK Threat Group Parser

A high-performance Python tool for SOC analysts and Threat Intelligence researchers to aggregate, filter, and deduplicate APT group data from multiple authoritative sources.
Combines structured data from MITRE ATT&CK (v18.1+) with the community-driven APT Groups & Operations spreadsheet (scanning all regional tabs) to provide a unified, verified list of threat actors targeting specific sectors.

### Key Features
- Multi-Source Aggregation: Simultaneously queries:
- Official MITRE ATT&CK releases (configurable version).
- APT Groups & Operations Google Sheet (automatically scans all 8+ regional tabs).
- Smart Deduplication: Automatically merges duplicates. If a group exists in both sources, it prioritizes the rich structured data from MITRE while flagging it as "Verified by Multiple Sources".
- Sector-Specific Search: Enhanced lookup with synonyms (e.g., searching healthcare also matches medical, hospital, pharma, медицина).
- 
### Quick Start
Python 3.6+
requests

``` pip install requests ```

1. Run the scanner
``` python ti_parser.py ```
2. Enter your target keyword (e.g., healthcare, energy, finance).

### Example
```
--- Global Threat Intel Parser (v18.1 + All Regions) ---
Enter keyword: healthcare

[*] Loading MITRE ATT&CK v18.1...
[+] Found in MITRE: 14
[*] Scanning 8 regions in Google Sheets...
[+] Found in Google Sheets (raw): 22

==================== UNIQUE GROUPS: 18 ====================
[1] ✅ APT29
    Sources: MITRE, Google Sheet
    MITRE ID: G0016
    Details: Targets government, healthcare, and think tanks...
...
```

### Configuration
```
Target MITRE Version
VERSION = "18.1" 

# Specific Google Sheet Region IDs (pre-configured for full coverage)
REGION_GIDS = [
    "361554658", "1636225066", "1905351590", 
    "376438690", "300065512", "2069598202", 
    "574287636", "438782970"
```
