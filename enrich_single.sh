#!/bin/bash

# =================================================================
# Script Name: enrich_single.sh
# Description: Rapid Single-IP Triage via AlienVault OTX API
# Usage: OTX_KEY=your_key ./enrich_single.sh 1.2.3[.]4
# =================================================================

# Check if an IP address was provided as a command-line argument
if [ -z "$1" ]; then
    echo "Error: No IP address provided."
    echo "Usage: OTX_KEY=your_key ./enrich_single.sh <IP_ADDRESS>"
    exit 1
fi

# Security Check: Ensure API Key is provided
if [ -z "$OTX_KEY" ]; then
    echo "Error: OTX_KEY environment variable is not set."
    exit 1
fi

# Configuration and sanitization
API_KEY="$OTX_KEY"
IP=$(echo "$1" | tr -d '[]') # Instantly clean any brackets from the input
FULL_JSON="single_ip_enrichment.json"
MITRE_FILE="single_ip_mitre.txt"

echo "[*] Investigating Indicator: $IP"

# Perform API Request
RAW_DATA=$(curl -s -H "X-OTX-API-KEY: $API_KEY" \
    "https://otx.alienvault.com/api/v1/indicators/IPv4/$IP/general")

# 1. Generate Indented JSON report
echo "$RAW_DATA" | jq . > "$FULL_JSON"

# 2. Generate MITRE ATT&CK Summary
echo "--- MITRE ATT&CK Mapping for $IP ---" > "$MITRE_FILE"
MAPPINGS=$(echo "$RAW_DATA" | jq -r '.. | .attack_ids? | select(. != null) | .[] | .display_name' | sort -u)

if [ -z "$MAPPINGS" ]; then
    echo "No MITRE techniques found for this IP." >> "$MITRE_FILE"
else
    echo "$MAPPINGS" >> "$MITRE_FILE"
fi

echo "Investigation complete."
echo "Full data: $FULL_JSON"
echo "MITRE Mapping: $MITRE_FILE"