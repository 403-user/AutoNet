# AutoNet Examples

## Quick Discovery (non-root)

Ping-sweep a /24 subnet to find live hosts (no port scan):

```bash
autonet --targets 192.168.1.0/24 --ports 22 --timeout 5
```

## Scan Home Network (non-root)

Common ports on a typical home LAN:

```bash
autonet --targets 192.168.1.0/24 \
  --ports "22,80,443,445,3389,8080,8443,9090" \
  --output home_scan.json
```

## Full Audit (root, most thorough)

SYN scan + version detection + CVE matching on all top-1000 ports:

```bash
sudo autonet --targets 10.0.0.0/24 \
  --ports top1000 \
  --output full_audit.json \
  --rate 50 \
  --timeout 60 \
  --verbose
```

## Specific Host + Service Scan

Deep scan of a single host with a custom port list:

```bash
autonet --targets 10.129.1.252 \
  --ports "22,80,443,8080,8443,3306,6379,27017" \
  --output single_host.json \
  --rate 10 \
  --timeout 30
```

## Fast Discover-Only

Find alive hosts on a /16 subnet quickly — no port scan:

```bash
sudo autonet --targets 10.0.0.0/16 --ports 22 --timeout 5 --output alive_hosts.json
```

## Docker: Scan from Container

```bash
# Build
docker build -t autonet .

# Host-network scan (required for ARP discovery)
docker run --network=host \
  -v $(pwd):/data \
  autonet --targets 192.168.1.0/24 --output /data/scan.json

# Non-root scan (TCP connect only)
docker run -v $(pwd):/data \
  autonet --targets 10.0.0.1 --output /data/scan.json
```

## CSV Output for Spreadsheets

```bash
autonet --targets 10.0.0.0/24 \
  --ports top100 \
  --format csv \
  --output report.csv
```

## Verbose / Debug Mode

```bash
autonet --targets 192.168.1.1 --ports 80,443 --output debug.json --verbose
```
