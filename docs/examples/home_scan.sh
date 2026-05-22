#!/usr/bin/env bash
# Scan typical home network
# Adjust the subnet to match your LAN

sudo autonet \
  --targets 192.168.1.0/24 \
  --ports "22,80,443,445,3389,8080,8443,9090" \
  --output home_network_report.json \
  --rate 30 \
  --timeout 20 \
  --verbose
