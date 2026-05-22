# AutoNet Architecture

## Layered Design

AutoNet follows a strict layered architecture. Each phase is independent, communicating via well-defined data models.

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI (cli.py)                        │
│               argparse entry point → config                 │
└─────────────────────────┬───────────────────────────────────┘
                          │ ScanConfig
┌─────────────────────────▼───────────────────────────────────┐
│                    Scanner (scanner.py)                     │
│                    Orchestrator: run()                     │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  Discovery    │  │ Enumeration  │  │  Vuln Matching   │  │
│  │  (Who?)       │→ │  (What?)     │→ │  (Risks?)        │→ │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
│                                          │                  │
│  ┌──────────────┐                        │                  │
│  │  Reporting   │◄───────────────────────┘                  │
│  │  (Outcome)   │                                           │
│  └──────────────┘                                           │
└─────────────────────────────────────────────────────────────┘
```

## Data Flow

```
CLI args
   │
   ▼
ScanConfig ──► Scanner.orchestrate()
                   │
              ┌────┴────┐
              │ Discovery│  ← ARP (root) / nmap -sn (user)
              └────┬────┘
                   │ List[Host] (ip, mac, is_alive)
              ┌────┴────┐
              │Enumera- │  ← python-nmap -sS (root) / -sT (user)
              │  tion   │    with -sV (version detection)
              └────┬────┘
                   │ Host.services = [Service(port, proto, name, version)]
              ┌────┴────┐
              │  Vuln   │  ← aiohttp → Vulners API (async, rate-limited)
              │ Match   │
              └────┬────┘
                   │ Host.vulnerabilities = [Vulnerability(cve_id, score, desc)]
              ┌────┴────┐
              │ Report  │  ← JSON or CSV file
              └────┬────┘
                   ▼
            autonet_report.json/.csv
```

## Package Map

```
autonet/
├── cli.py                   # argparse CLI
├── config.py                # ScanConfig dataclass + validation
├── scanner.py               # Orchestrator
├── discovery/
│   ├── base.py              # AbstractBaseDiscoverer
│   ├── arp.py               # ARP sweep (scapy, root)
│   └── ping.py              # nmap -sn / TCP probe (non-root)
├── enumeration/
│   ├── base.py              # AbstractBaseEnumerator
│   └── port_scanner.py      # python-nmap wrapper
├── vuln_matching/
│   ├── base.py              # AbstractBaseVulnMatcher
│   ├── cve_lookup.py        # Async Vulners API client
│   └── matcher.py           # Convenience alias
├── reporting/
│   ├── base.py              # AbstractBaseReporter
│   ├── json_reporter.py     # Structured JSON output
│   └── csv_reporter.py      # Flat CSV per-service/per-CVE
├── models/
│   ├── host.py              # Host dataclass
│   ├── service.py           # Service dataclass
│   └── vulnerability.py     # Vulnerability dataclass
└── utils/
    ├── network.py           # CIDR iteration, private IP check
    └── logger.py            # Logging config
```

## Key Design Decisions

| Decision | Rationale |
|---|---|
| **Dual-mode privilege** | Auto-detect root; SYN scan + ARP if root, else TCP connect + nmap -sn |
| **Async Vuln matching** | Vulners API calls are I/O-bound; async with rate limiting prevents blocking |
| **Strategy pattern** | Each phase uses an abstract base + concrete implementations — swap implementations without changing the orchestrator |
| **Dataclass models** | Immutable, self-documenting data structures passed between layers |
| **nmap XML/object API** | `python-nmap` returns structured data — avoids fragile stdout parsing |

## Docker Usage

```bash
# Build
docker build -t autonet .

# Scan with host networking (required for ARP)
docker run --network=host -v $(pwd):/data autonet --targets 192.168.1.0/24 --output /data/report.json

# Non-ARP scan (standard networking)  docker run -v $(pwd):/data autonet --targets 10.0.0.1 --output /data/report.json
```
