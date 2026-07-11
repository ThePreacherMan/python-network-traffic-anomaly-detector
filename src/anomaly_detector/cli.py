"""Command-line interface for the network traffic anomaly detector."""

import argparse
import json
import sys
from pathlib import Path

from anomaly_detector.analyzer import TrafficAnalyzer
from anomaly_detector.loader import TrafficDataError


def build_parser() -> argparse.ArgumentParser:
    """Create and configure the command-line argument parser."""

    parser = argparse.ArgumentParser(
        prog="network-anomaly-detector",
        description=(
            "Analyze network traffic CSV files and identify "
            "suspicious activity."
        ),
    )

    parser.add_argument(
        "file",
        type=Path,
        help="Path to the network traffic CSV file",
    )

    parser.add_argument(
        "--anomalies-only",
        action="store_true",
        help="Display only traffic flows classified as anomalies",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output analysis results as JSON",
    )

    return parser


def print_text_results(results: list) -> None:
    """Print analysis results in a readable terminal format."""

    for index, result in enumerate(results, start=1):
        flow = result.flow

        print(f"\nResult #{index}")
        print("-" * 60)
        print(
            f"Connection: {flow.source_ip}:{flow.source_port} -> "
            f"{flow.destination_ip}:{flow.destination_port}"
        )
        print(f"Protocol: {flow.protocol.upper()}")
        print(f"Total bytes: {flow.total_bytes}")
        print(f"Packets: {flow.packets}")
        print(f"Anomaly: {'YES' if result.is_anomaly else 'NO'}")
        print(f"Score: {result.anomaly_score:.2f}")
        print(f"Severity: {result.severity.upper()}")
        print(f"Reason: {result.reason}")


def main() -> int:
    """Run the command-line application."""

    parser = build_parser()
    args = parser.parse_args()

    analyzer = TrafficAnalyzer()

    try:
        results = analyzer.analyze_file(args.file)
    except (FileNotFoundError, TrafficDataError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.anomalies_only:
        results = analyzer.anomalies_only(results)

    if args.json:
        print(
            json.dumps(
                [result.to_dict() for result in results],
                indent=2,
            )
        )
    else:
        print_text_results(results)

        summary = analyzer.severity_summary(results)

        print("\nSeverity Summary")
        print("-" * 60)

        for severity, count in summary.items():
            print(f"{severity}: {count}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
