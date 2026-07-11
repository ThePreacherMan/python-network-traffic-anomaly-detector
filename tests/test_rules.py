"""Tests for the rule-based network anomaly detector."""

from datetime import datetime

from anomaly_detector.models import NetworkFlow
from anomaly_detector.rules import DetectionThresholds, RuleBasedDetector


def build_flow(**overrides: object) -> NetworkFlow:
    """Create a valid network flow for detector tests."""

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


def test_normal_flow_is_not_flagged() -> None:
    """Ordinary traffic should remain informational."""

    detector = RuleBasedDetector()
    result = detector.analyze(build_flow())

    assert result.is_anomaly is False
    assert result.anomaly_score == 0.0
    assert result.severity == "INFO"
    assert result.reason == "No suspicious rule-based behavior detected"


def test_high_transfer_volume_is_detected() -> None:
    """Large transfers should trigger an anomaly."""

    detector = RuleBasedDetector()
    result = detector.analyze(
        build_flow(
            bytes_sent=9_000_000,
            bytes_received=2_000_000,
        )
    )

    assert result.is_anomaly is True
    assert result.anomaly_score == 0.30
    assert result.severity == "LOW"
    assert "High data transfer volume detected" in result.reason


def test_suspicious_destination_port_is_detected() -> None:
    """Monitored destination ports should trigger an alert."""

    detector = RuleBasedDetector()
    result = detector.analyze(build_flow(destination_port=3389))

    assert result.is_anomaly is True
    assert result.anomaly_score == 0.20
    assert result.severity == "LOW"
    assert "monitored destination port 3389" in result.reason


def test_multiple_rules_increase_severity() -> None:
    """Multiple suspicious behaviors should produce a higher score."""

    detector = RuleBasedDetector()
    result = detector.analyze(
        build_flow(
            destination_port=4444,
            bytes_sent=25_000_000,
            bytes_received=1_500_000,
            duration_seconds=4.0,
            packets=62_000,
        )
    )

    assert result.is_anomaly is True
    assert result.anomaly_score == 1.0
    assert result.severity == "CRITICAL"
    assert "High data transfer volume detected" in result.reason
    assert "Unusually high packet count detected" in result.reason
    assert "Unusually high transfer rate detected" in result.reason
    assert "monitored destination port 4444" in result.reason


def test_long_running_connection_is_detected() -> None:
    """Connections exceeding the configured duration should be flagged."""

    detector = RuleBasedDetector()
    result = detector.analyze(
        build_flow(duration_seconds=3_600.0)
    )

    assert result.is_anomaly is True
    assert result.anomaly_score == 0.15
    assert result.severity == "LOW"
    assert "Long-running connection detected" in result.reason


def test_custom_thresholds_are_respected() -> None:
    """The detector should support custom security thresholds."""

    thresholds = DetectionThresholds(
        high_bytes_threshold=1_000,
        high_packet_threshold=100,
        high_rate_threshold=500.0,
        long_duration_threshold=60.0,
        suspicious_destination_ports=(8080,),
    )

    detector = RuleBasedDetector(thresholds)

    result = detector.analyze(
        build_flow(
            destination_port=8080,
            bytes_sent=800,
            bytes_received=400,
            duration_seconds=1.0,
            packets=150,
        )
    )

    assert result.is_anomaly is True
    assert result.anomaly_score == 1.0
    assert result.severity == "CRITICAL"


def test_analyze_many_returns_result_for_each_flow() -> None:
    """Batch analysis should preserve the number of input flows."""

    detector = RuleBasedDetector()

    flows = [
        build_flow(),
        build_flow(destination_port=22),
        build_flow(bytes_sent=11_000_000),
    ]

    results = detector.analyze_many(flows)

    assert len(results) == 3
    assert results[0].is_anomaly is False
    assert results[1].is_anomaly is True
    assert results[2].is_anomaly is True
