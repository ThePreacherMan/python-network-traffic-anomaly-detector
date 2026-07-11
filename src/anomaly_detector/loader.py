"""Utilities for loading network traffic data from CSV files."""

import csv
from datetime import datetime
from pathlib import Path

from anomaly_detector.models import NetworkFlow

REQUIRED_COLUMNS = {
    "timestamp",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "bytes_sent",
    "bytes_received",
    "duration_seconds",
    "packets",
}


class TrafficDataError(ValueError):
    """Raised when network traffic data cannot be parsed safely."""


def parse_timestamp(value: str) -> datetime:
    """Parse an ISO 8601 timestamp."""

    try:
        return datetime.fromisoformat(value.strip())
    except ValueError as exc:
        raise TrafficDataError(
            f"Invalid timestamp value: {value!r}"
        ) from exc


def row_to_network_flow(row: dict[str, str], row_number: int) -> NetworkFlow:
    """Convert one CSV row into a validated NetworkFlow object."""

    try:
        return NetworkFlow(
            timestamp=parse_timestamp(row["timestamp"]),
            source_ip=row["source_ip"].strip(),
            destination_ip=row["destination_ip"].strip(),
            source_port=int(row["source_port"]),
            destination_port=int(row["destination_port"]),
            protocol=row["protocol"].strip().upper(),
            bytes_sent=int(row["bytes_sent"]),
            bytes_received=int(row["bytes_received"]),
            duration_seconds=float(row["duration_seconds"]),
            packets=int(row["packets"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise TrafficDataError(
            f"Invalid traffic data on CSV row {row_number}: {exc}"
        ) from exc


def load_network_flows(file_path: str | Path) -> list[NetworkFlow]:
    """Load and validate network flows from a CSV file."""

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Traffic data file not found: {path}")

    if not path.is_file():
        raise TrafficDataError(f"Traffic data path is not a file: {path}")

    flows: list[NetworkFlow] = []

    try:
        with path.open("r", encoding="utf-8", newline="") as csv_file:
            reader = csv.DictReader(csv_file)

            if reader.fieldnames is None:
                raise TrafficDataError("CSV file does not contain a header row")

            normalized_columns = {
                column.strip() for column in reader.fieldnames
            }

            missing_columns = REQUIRED_COLUMNS - normalized_columns

            if missing_columns:
                missing = ", ".join(sorted(missing_columns))
                raise TrafficDataError(
                    f"CSV file is missing required columns: {missing}"
                )

            for row_number, row in enumerate(reader, start=2):
                flows.append(row_to_network_flow(row, row_number))

    except UnicodeDecodeError as exc:
        raise TrafficDataError(
            f"Unable to decode CSV file as UTF-8: {path}"
        ) from exc

    if not flows:
        raise TrafficDataError("CSV file does not contain any traffic records")

    return flows
