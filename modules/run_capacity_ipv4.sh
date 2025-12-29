#!/bin/bash

# Configuration Variables
MGR="localhost"
SSID="2G_TEST_HFCL"
PASS="1234567890"
UPSTREAM="1.1.eth2"
STA_PREFIX="sta"
DURATION=600000 # 10 minutes in ms
OUT_ROOT="/home/lanforge/Desktop/CapacityRuns"

# Test Scenarios: Protocol, DL_Rate, UL_Rate, Label
SCENARIOS=(
    "UDP-IPv4 1000Mbps 0bps UDP_DOWNLOAD"
    "UDP-IPv4 0bps 1000Mbps UDP_UPLOAD"
    "TCP-IPv4 1000Mbps 0bps TCP_DOWNLOAD"
    "TCP-IPv4 0bps 1000Mbps TCP_UPLOAD"
)

for SCENARIO in "${SCENARIOS[@]}"; do
    read -r PROTO DL UL LABEL <<< "$SCENARIO"
    
    echo "=========================================================="
    echo "STARTING TEST: $LABEL ($PROTO)"
    echo "=========================================================="

    python3 capacity_tester.py \
        --mgr "$MGR" \
        --upstream "$UPSTREAM" \
        --use_existing_stas \
        --sta_prefix "$STA_PREFIX" \
        --max_stas 1 \
        --protocol "$PROTO" \
        --download_rate "$DL" \
        --upload_rate "$UL" \
        --duration "$DURATION" \
        --outdir "$OUT_ROOT/$LABEL" \
        --ssid "$SSID" \
        --password "$PASS"

    echo "Finished $LABEL. Waiting 10 seconds for cooldown..."
    sleep 10
done

echo "All 4 scenarios completed successfully."
