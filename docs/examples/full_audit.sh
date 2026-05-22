#!/usr/bin/env bash
# Full network audit - requires root for SYN scan
# Scans top 1000 ports with version detection and CVE matching

sudo autonet \
  --targets 10.0.0.0/24 \
  --ports top1000 \
  --output full_audit.json \
  --rate 50 \
  --timeout 60 \
  --verbose
