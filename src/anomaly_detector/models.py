"""Data models used by the network traffic anomaly detector."""

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class NetworkFlow:
    """Represent a summarized network connection or traffic flow."""

    timestamp: datetime
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    bytes_sent: int
    bytes_received: int
    duration_seconds: float
    packets: int

    def __post_init__(self) -> None:
        """Validate network-flow values after initialization."""
        if not self.source_ip.strip():
            raise ValueError("source_ip cannot be empty")

        if not self.destination_ip.strip():
            raise ValueError("destination_ip cannot be empty")

        if not 0 <= self.source_port <= 65535:
            raise ValueError("source_port must be between 0 and 65535")

        if not 0 <= self.destination_port <= 65535:
            raise ValueError("destination_port must be between 0 and 65535")

        if self.bytes_sent < 0:
            raise ValueError("bytes_sent cannot be negative")

        if self.bytes_received < 0:
            raise ValueError("bytes_received cannot be negative")

        if self.duration_seconds < 0:
            raise ValueError("duration_seconds cannot be negative")

        if self.packets < 0:
            raise ValueError("packets cannot be negative")

        if not self.protocol.strip():
            raise ValueError("protocol cannot be empty")

    @property
    def total_bytes(self) -> int:
        """Return the total number of bytes transferred."""
        return self.bytes_sent + self.bytes_received

    @property
    def bytes_per_second(self) -> float:
        """Return the average transfer rate for the flow."""
        if self.duration_seconds == 0:
            return float(self.total_bytes)

        return self.total_bytes / self.duration_seconds

    def to_dict(self) -> dict[str, Any]:
        """Convert the network flow into a serializable dictionary."""
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        data["protocol"] = self.protocol.upper()
        data["total_bytes"] = self.total_bytes
        data["bytes_per_second"] = self.bytes_per_second
        return data


@dataclass(frozen=True, slots=True)
class AnomalyResult:
    """Represent the anomaly-analysis result for one network flow."""

    flow: NetworkFlow
    is_anomaly: bool
    anomaly_score: float
    severity: str
    reason: str

    def __post_init__(self) -> None:
        """Validate anomaly-result values."""
        allowed_severities = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

        if self.severity.upper() not in allowed_severities:
            raise ValueError(
                f"severity must be one of: {', '.join(sorted(allowed_severities))}"
            )

        if not self.reason.strip():
            raise ValueError("reason cannot be empty")

    def to_dict(self) -> dict[str, Any]:
        """Convert the anomaly result into a serializable dictionary."""
        return {
            "flow": self.flow.to_dict(),
            "is_anomaly": self.is_anomaly,
            "anomaly_score": self.anomaly_score,
            "severity": self.severity.upper(),
            "reason": self.reason,
        }
