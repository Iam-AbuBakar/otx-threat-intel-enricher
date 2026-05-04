OTX Threat Intel Enricher
A set of Bash utilities designed for Security Operations Center (SOC) analysts and Threat Hunters to automate IP address enrichment and MITRE ATT&CK mapping via the AlienVault OTX API.

Purpose
Investigation workflows often involve analyzing dozens of "defanged" IP addresses (e.g., 1.2.3[.]4). This toolkit automates:

Input Sanitization: Instantly removes brackets [] from single IPs or bulk lists.

Bulk Processing: Efficiently enriches entire datasets from a text file.

MITRE ATT&CK Mapping: Parses complex JSON pulses to extract specific Technique IDs and Names.

Prerequisites
These scripts require curl and jq. Install them via:

Bash
sudo apt update && sudo apt install jq curl -y
How to Run
To maintain security, these scripts use an environment variable (OTX_KEY) for your API key. This prevents your private key from being saved in your bash history or hardcoded into the scripts.

Option A: Bulk Enrichment (List of IPs)
Use this script when you have a large list of indicators. It reads from a file named ip8.txt.

Command:

Bash
export OTX_KEY="your_actual_api_key" && chmod +x enrich_list.sh && ./enrich_list.sh
Output: otx_full_enrichment.json and mitre_attack_summary.txt.

Option B: Quick Triage (Single IP)
Use this for a fast, one-off investigation of a specific indicator without editing any files.

Command:

Bash
export OTX_KEY="your_actual_api_key" && chmod +x enrich_single.sh && ./enrich_single.sh 157.20.182.75
Output: single_ip_enrichment.json and single_ip_mitre.txt.

📊 Output Descriptions
Full JSON Enrichment: Contains the complete technical profile of the IP, including Reputation, ASN, Geography, and all associated Threat Pulses.

MITRE Mapping: A filtered summary of specific adversary tactics and techniques (TTPs) linked to the IP, such as T1110 - Brute Force or T1071 - Application Layer Protocol.
