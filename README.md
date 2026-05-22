AutoNet: Modular Network Vulnerability Scanner

AutoNet is a high-performance, modular network vulnerability scanner designed for systems architects and security engineers. It automates the workflow of host discovery, service enumeration, and CVE matching, with a clean, extensible architecture.
🚀 Key Features

    Privilege-Aware Scanning: Automatically detects permissions. Use root for raw socket access (ARP/SYN scans) or non-root for standard TCP connect scans.

    Asynchronous Engine: Built with asyncio to minimize scan times, using semaphores to manage API rate limits gracefully.

    Intelligent Enumeration: Wraps nmap logic to provide comprehensive service version detection.

    CVE Matching: Integrated with the Vulners API for real-time vulnerability lookups.

    Containerized: Built with a multi-stage Dockerfile for environment consistency and deployment portability.

📋 Prerequisites

    Python 3.11+

    Nmap (must be installed on the host system)

    Git

⚙️ Installation
Bash

# Clone the repository
git clone https://github.com/YOUR_USERNAME/AutoNet.git
cd AutoNet

# Setup virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install .

💻 Usage
Non-Root (Standard Scan)

Ideal for standard user environments. Uses TCP Connect scans.
Bash

autonet --targets 192.168.1.0/24 --ports 22,80,443 --output report.json

Root (Full Capability)

Grants access to raw packet manipulation for faster ARP discovery and stealthier SYN scans.
Bash

sudo autonet --targets 10.0.0.0/24 --rate 50 --output report.csv

Docker Deployment

Ensure you run with host networking to allow the container access to the local network stack.
Bash

docker build -t autonet .
docker run --network=host autonet --targets 192.168.1.0/24

📂 Architecture

The project follows a clean, modular design to ensure maintainability:
Plaintext

autonet/
├── cli.py              # CLI Entry point
├── config.py           # Configuration & Validation
├── scanner.py          # Orchestrator
├── discovery/          # ARP / ICMP Probes
├── enumeration/        # Nmap wrappers
├── vuln_matching/      # Vulners API Client
├── reporting/          # JSON/CSV Output
└── models/             # Data structure definitions

⚠️ Legal and Ethical Warning

Disclaimer: This tool is for educational and authorized security testing purposes only. Using this tool to scan networks or devices without explicit, written permission from the owner is illegal and unethical. The author assumes no liability for misuse of this software. Always ensure your testing scope is strictly defined and authorized.
🛠️ Development & Testing

To run the full test suite:
Bash

pytest tests/

How to use this:

    Create a file named README.md in the root of your AutoNet/ directory.

    Paste the text above into the file.

    Replace YOUR_USERNAME in the clone/remote URLs with your actual GitHub username.

    Save and commit the file:
    Bash

    git add README.md
    git commit -m "Add documentation"
    git push origin main
