"""Tests for network traffic data models."""

from datetime import datetime

import pytest

from anomaly_detector.models import AnomalyResult, NetworkFlow


def build_flow(**overrides: object) -> NetworkFlow:
    """Create a valid NetworkFlow for testing."""

    values = {
        "timestamp": datetime.fromisoformat("2026-07-10T08:00:00"),
        "source_ip": "192.168.1.10",
        "destination_ip": "8.8.8.8",
        "source_port": 51514,
        "destination_port": 53,
        "protocol": "udp",
        "bytes_sent": 120,
        "bytes_received": 240,
        "duration_seconds": 0.15,
        "packets": 4,
    }

    values.update(overrides)
    return NetworkFlow(**values)


def test_total_bytes_is_calculated_correctly() -> None:
    """Total bytes should combine sent and received traffic."""

    flow = build_flow(bytes_sent=500, bytes_received=1_500)

    assert flow.total_bytes == 2_000


def test_bytes_per_second_is_calculated_correctly() -> None:
    """Transfer rate should use total bytes divided by duration."""

    flow = build_flow(
        bytes_sent=500,
        bytes_received=500,
        duration_seconds=2.0,
    )

    assert flow.bytes_per_second == 500.0


def test_zero_duration_uses_total_bytes_as_rate() -> None:
    """Zero-duration flows should not cause division errors."""

    flow = build_flow(
        bytes_sent=500,
        bytes_received=500,
        duration_seconds=0.0,
    )

    assert flow.bytes_per_second == 1_000.0


def test_network_flow_to_dict_is_serializable() -> None:
    """NetworkFlow should produce normalized dictionary output."""

    flow = build_flow(protocol="tcp")
    data = flow.to_dict()

    assert data["timestamp"] == "2026-07-10T08:00:00"
    assert data["protocol"] == "TCP"
    assert data["total_bytes"] == 360
    assert data["bytes_per_second"] == 2_400.0


@pytest.mark.parametrize(
    ("field", "value", "expected_message"),
    [
        ("source_ip", "", "source_ip cannot be empty"),
        ("destination_ip", "   ", "destination_ip cannot be empty"),
        ("source_port", -1, "source_port must be between 0 and 65535"),
        ("destination_port", 65_536, "destination_port must be between 0 and 65535"),
        ("bytes_sent", -1, "bytes_sent cannot be negative"),
        ("bytes_received", -1, "bytes_received cannot be negative"),
        ("duration_seconds", -1.0, "duration_seconds cannot be negative"),
        ("packets", -1, "packets cannot be negative"),
        ("protocol", "", "protocol cannot be empty"),
    ],
)
def test_invalid_network_flow_values_raise_errors(
    field: str,
    value: object,
    expected_message: str,
) -> None:
    """Invalid network values should be rejected."""

    with pytest.raises(ValueError, match=expected_message):
        build_flow(**{field: value})


def test_anomaly_result_to_dict_contains_flow_details() -> None:
    """AnomalyResult should serialize its analysis and original flow."""

    result = AnomalyResult(
        flow=build_flow(),
        is_anomaly=True,
        anomaly_score=0.75,
        severity="high",
        reason="Suspicious transfer pattern",
    )

    data = result.to_dict()

    assert data["is_anomaly"] is True
    assert data["anomaly_score"] == 0.75
    assert data["severity"] == "HIGH"
    assert data["reason"] == "Suspicious transfer pattern"
    assert data["flow"]["source_ip"] == "192.168.1.10"


def test_invalid_severity_raises_error() -> None:
    """Unsupported severity names should be rejected."""

    with pytest.raises(ValueError, match="severity must be one of"):
        AnomalyResult(
            flow=build_flow(),
            is_anomaly=True,
            anomaly_score=0.5,
            severity="urgent",
            reason="Invalid severity test",
        )


def test_empty_reason_raises_error() -> None:
    """Anomaly results must include an explanation."""

    with pytest.raises(ValueError, match="reason cannot be empty"):
        AnomalyResult(
            flow=build_flow(),
            is_anomaly=False,
            anomaly_score=0.0,
            severity="INFO",
            reason="",
        )
