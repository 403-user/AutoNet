#!/usr/bin/env bash
# Fast discovery - find which hosts are alive on a subnet
# Uses ARP sweep (root) or ping sweep via nmap -sn

autonet \
  --targets 192.168.1.0/24 \
  --ports 22 \
  --output discovery.json \
  --timeout 5 \
  --verbose
