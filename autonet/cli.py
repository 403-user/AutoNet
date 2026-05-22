import argparse
import sys

from autonet.config import build_config
from autonet.scanner import Scanner
from autonet.utils.logger import setup_logger


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="autonet",
        description="AutoNet - Network Vulnerability Scanner",
    )
    parser.add_argument(
        "--targets",
        required=True,
        help="CIDR range (e.g. 192.168.1.0/24) or comma-separated IPs",
    )
    parser.add_argument(
        "--ports",
        default="top100",
        help="Ports: 'top100', 'top1000', range like '1-1000', or '22,80,443'",
    )
    parser.add_argument(
        "--output",
        default="autonet_report.json",
        help="Output file path",
    )
    parser.add_argument(
        "--format",
        choices=["json", "csv"],
        default="json",
        help="Output format",
    )
    parser.add_argument(
        "--rate",
        type=int,
        default=50,
        help="Max concurrent scan tasks",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Per-host timeout in seconds",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable debug logging",
    )
    return parser


def main():
    parser = create_parser()
    args = parser.parse_args()

    logger = setup_logger(verbose=args.verbose)
    logger.info("AutoNet starting")

    try:
        config = build_config(args)
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        sys.exit(1)

    scanner = Scanner(config)
    results = scanner.run()
    scanner.report(results)
    logger.info(f"Scan complete. Report written to {config.output_path}")


if __name__ == "__main__":
    main()
