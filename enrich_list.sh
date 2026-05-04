#!/bin/bash

# =================================================================
# Script Name: enrich_list.sh
# Description: Bulk IP enrichment via AlienVault OTX API
# Author: [Abu Bakar]
# =================================================================

# Configuration
API_KEY="$OTX_KEY"
INPUT_FILE="your_ip.txt"
FULL_JSON="otx_full_enrichment.json"
MITRE_FILE="mitre_attack_summary.txt"

# Security Check: Ensure API Key is provided via Environment Variable
if [ -z "$OTX_KEY" ]; then
    echo "Error: OTX_KEY environment variable is not set."
    echo "Usage: export OTX_KEY='your_api_key_here' && ./enrich_list.sh"
    exit 1
fi

# Check if the input file exists in the current directory
if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: $INPUT_FILE not found! Please ensure your IPs are in a file named ip8.txt."
    exit 1
fi

# Initialize files: Create/Clear results and start JSON array
echo "[" > "$FULL_JSON"
> "$MITRE_FILE"

echo "--- Starting Bulk OTX Enrichment ---"

# Process IPs: Remove brackets [] from source text and iterate
cat "$INPUT_FILE" | tr -d '[]' | while read -r ip; do
    # Skip lines that are empty after cleaning
    [ -z "$ip" ] && continue
    
    echo "[*] Processing Indicator: $ip"
    
    # Execute API request and store raw response in memory
    RAW_DATA=$(curl -s -H "X-OTX-API-KEY: $API_KEY" \
        "https://otx.alienvault.com/api/v1/indicators/IPv4/$ip/general")
    
    # 1. Append formatted JSON to the enrichment file
    echo "--- IP: $ip ---" >> "$FULL_JSON"
    echo "$RAW_DATA" | jq . >> "$FULL_JSON"
    echo "," >> "$FULL_JSON"
    
    # 2. Extract Precise MITRE ATT&CK Mappings
    echo "--- IP: $ip ---" >> "$MITRE_FILE"
    
    # Deep search for attack_ids and extract display_name
    MAPPINGS=$(echo "$RAW_DATA" | jq -r '.. | .attack_ids? | select(. != null) | .[] | .display_name' | sort -u)
    
    if [ -z "$MAPPINGS" ]; then
        echo "No MITRE techniques found in OTX pulses for this IP." >> "$MITRE_FILE"
    else
        echo "$MAPPINGS" >> "$MITRE_FILE"
    fi
    
    # Add spacing between indicators for readability
    echo -e "\n" >> "$MITRE_FILE"
done

# Finalize the JSON array structure
echo "{}]" >> "$FULL_JSON"

echo "--- Process Complete ---"
echo "Comprehensive data saved to: $FULL_JSON"
echo "MITRE summary saved to: $MITRE_FILE"