"""Tests for the high-level network traffic analyzer."""

from datetime import datetime
from pathlib import Path

from anomaly_detector.analyzer import TrafficAnalyzer
from anomaly_detector.models import NetworkFlow
from anomaly_detector.rules import DetectionThresholds


def build_flow(**overrides: object) -> NetworkFlow:
    """Create a valid network flow for analyzer tests."""

    values = {
        "timestamp": datetime.fromisoformat("2026-07-10T08:00:00"),
        "source_ip": "192.168.1.10",
        "destination_ip": "8.8.8.8",
        "source_port": 51514,
        "destination_port": 53,
        "protocol": "UDP",
        "bytes_sent": 120,
        "bytes_received": 240,
        "duration_seconds": 0.15,
        "packets": 4,
    }

    values.update(overrides)
    return NetworkFlow(**values)


def write_csv(tmp_path: Path) -> Path:
    """Create a temporary traffic CSV file."""

    file_path = tmp_path / "traffic.csv"

    file_path.write_text(
        (
            "timestamp,source_ip,destination_ip,source_port,"
            "destination_port,protocol,bytes_sent,bytes_received,"
            "duration_seconds,packets\n"
            "2026-07-10T08:00:00,192.168.1.10,8.8.8.8,"
            "51514,53,UDP,120,240,0.15,4\n"
            "2026-07-10T08:05:00,192.168.1.20,203.0.113.50,"
            "52000,4444,TCP,25000000,1500000,4.0,62000\n"
        ),
        encoding="utf-8",
    )

    return file_path


def test_analyze_flows_returns_results_for_all_flows() -> None:
    """The analyzer should return one result per network flow."""

    analyzer = TrafficAnalyzer()

    flows = [
        build_flow(),
        build_flow(destination_port=22),
    ]

    results = analyzer.analyze_flows(flows)

    assert len(results) == 2
    assert results[0].is_anomaly is False
    assert results[1].is_anomaly is True


def test_analyze_file_loads_and_analyzes_csv(
    tmp_path: Path,
) -> None:
    """The analyzer should process traffic directly from a CSV file."""

    analyzer = TrafficAnalyzer()
    file_path = write_csv(tmp_path)

    results = analyzer.analyze_file(file_path)

    assert len(results) == 2
    assert results[0].severity == "INFO"
    assert results[1].severity == "CRITICAL"


def test_anomalies_only_filters_normal_results() -> None:
    """Only anomalous results should remain after filtering."""

    analyzer = TrafficAnalyzer()

    results = analyzer.analyze_flows(
        [
            build_flow(),
            build_flow(destination_port=3389),
            build_flow(bytes_sent=11_000_000),
        ]
    )

    anomalies = analyzer.anomalies_only(results)

    assert len(anomalies) == 2
    assert all(result.is_anomaly for result in anomalies)


def test_severity_summary_counts_results_correctly() -> None:
    """Severity summaries should count each classification."""

    analyzer = TrafficAnalyzer()

    results = analyzer.analyze_flows(
        [
            build_flow(),
            build_flow(destination_port=22),
            build_flow(
                destination_port=4444,
                bytes_sent=25_000_000,
                bytes_received=1_500_000,
                duration_seconds=4.0,
                packets=62_000,
            ),
        ]
    )

    summary = analyzer.severity_summary(results)

    assert summary["INFO"] == 1
    assert summary["LOW"] == 1
    assert summary["MEDIUM"] == 0
    assert summary["HIGH"] == 0
    assert summary["CRITICAL"] == 1


def test_custom_thresholds_are_used_by_analyzer() -> None:
    """The analyzer should pass custom thresholds to its detector."""

    thresholds = DetectionThresholds(
        high_bytes_threshold=100,
        high_packet_threshold=10_000,
        high_rate_threshold=10_000.0,
        long_duration_threshold=10_000.0,
        suspicious_destination_ports=(),
    )

    analyzer = TrafficAnalyzer(thresholds)

    results = analyzer.analyze_flows(
        [
            build_flow(
                bytes_sent=80,
                bytes_received=40,
            )
        ]
    )

    assert results[0].is_anomaly is True
    assert results[0].anomaly_score == 0.30
    assert results[0].severity == "LOW"
