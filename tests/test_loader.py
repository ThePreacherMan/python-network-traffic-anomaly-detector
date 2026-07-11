"""Tests for the CSV network traffic loader."""

from pathlib import Path

import pytest

from anomaly_detector.loader import (
    TrafficDataError,
    load_network_flows,
    parse_timestamp,
)


def write_csv(tmp_path: Path, content: str) -> Path:
    """Create a temporary CSV file for testing."""

    file_path = tmp_path / "traffic.csv"
    file_path.write_text(content, encoding="utf-8")
    return file_path


def test_parse_timestamp_accepts_iso_format() -> None:
    """ISO 8601 timestamps should be parsed correctly."""

    timestamp = parse_timestamp("2026-07-10T08:00:00")

    assert timestamp.year == 2026
    assert timestamp.month == 7
    assert timestamp.day == 10
    assert timestamp.hour == 8


def test_invalid_timestamp_raises_traffic_data_error() -> None:
    """Invalid timestamps should produce a clear parsing error."""

    with pytest.raises(TrafficDataError, match="Invalid timestamp value"):
        parse_timestamp("not-a-valid-date")


def test_load_network_flows_reads_valid_csv(tmp_path: Path) -> None:
    """A valid CSV file should return NetworkFlow objects."""

    file_path = write_csv(
        tmp_path,
        (
            "timestamp,source_ip,destination_ip,source_port,"
            "destination_port,protocol,bytes_sent,bytes_received,"
            "duration_seconds,packets\n"
            "2026-07-10T08:00:00,192.168.1.10,8.8.8.8,"
            "51514,53,udp,120,240,0.15,4\n"
        ),
    )

    flows = load_network_flows(file_path)

    assert len(flows) == 1
    assert flows[0].source_ip == "192.168.1.10"
    assert flows[0].destination_ip == "8.8.8.8"
    assert flows[0].protocol == "UDP"
    assert flows[0].total_bytes == 360


def test_missing_file_raises_file_not_found_error(
    tmp_path: Path,
) -> None:
    """A missing CSV file should be reported clearly."""

    missing_file = tmp_path / "missing.csv"

    with pytest.raises(FileNotFoundError, match="Traffic data file not found"):
        load_network_flows(missing_file)


def test_directory_path_is_rejected(tmp_path: Path) -> None:
    """A directory should not be accepted as a traffic file."""

    with pytest.raises(
        TrafficDataError,
        match="Traffic data path is not a file",
    ):
        load_network_flows(tmp_path)


def test_missing_required_columns_are_rejected(
    tmp_path: Path,
) -> None:
    """CSV files missing required columns should be rejected."""

    file_path = write_csv(
        tmp_path,
        (
            "timestamp,source_ip,destination_ip\n"
            "2026-07-10T08:00:00,192.168.1.10,8.8.8.8\n"
        ),
    )

    with pytest.raises(
        TrafficDataError,
        match="CSV file is missing required columns",
    ):
        load_network_flows(file_path)


def test_invalid_numeric_value_reports_row_number(
    tmp_path: Path,
) -> None:
    """Invalid numeric values should identify the affected CSV row."""

    file_path = write_csv(
        tmp_path,
        (
            "timestamp,source_ip,destination_ip,source_port,"
            "destination_port,protocol,bytes_sent,bytes_received,"
            "duration_seconds,packets\n"
            "2026-07-10T08:00:00,192.168.1.10,8.8.8.8,"
            "invalid,53,UDP,120,240,0.15,4\n"
        ),
    )

    with pytest.raises(
        TrafficDataError,
        match="Invalid traffic data on CSV row 2",
    ):
        load_network_flows(file_path)


def test_empty_csv_is_rejected(tmp_path: Path) -> None:
    """A CSV containing only headers should be rejected."""

    file_path = write_csv(
        tmp_path,
        (
            "timestamp,source_ip,destination_ip,source_port,"
            "destination_port,protocol,bytes_sent,bytes_received,"
            "duration_seconds,packets\n"
        ),
    )

    with pytest.raises(
        TrafficDataError,
        match="CSV file does not contain any traffic records",
    ):
        load_network_flows(file_path)


def test_csv_without_header_is_rejected(tmp_path: Path) -> None:
    """A completely empty CSV file should be rejected."""

    file_path = write_csv(tmp_path, "")

    with pytest.raises(
        TrafficDataError,
        match="CSV file does not contain a header row",
    ):
        load_network_flows(file_path)
