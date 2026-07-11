"""Rule-based detection logic for suspicious network traffic."""

from dataclasses import dataclass

from anomaly_detector.models import AnomalyResult, NetworkFlow


@dataclass(frozen=True, slots=True)
class DetectionThresholds:
    """Configurable thresholds used by the rule-based detector."""

    high_bytes_threshold: int = 10_000_000
    high_packet_threshold: int = 50_000
    high_rate_threshold: float = 5_000_000.0
    long_duration_threshold: float = 3_600.0
    suspicious_destination_ports: tuple[int, ...] = (
        21,
        22,
        23,
        445,
        1433,
        3389,
        4444,
        5900,
    )


class RuleBasedDetector:
    """Detect suspicious network flows using explainable rules."""

    def __init__(
        self,
        thresholds: DetectionThresholds | None = None,
    ) -> None:
        """Initialize the detector with configurable thresholds."""
        self.thresholds = thresholds or DetectionThresholds()

    def analyze(self, flow: NetworkFlow) -> AnomalyResult:
        """Analyze one network flow and return an anomaly result."""

        reasons: list[str] = []
        score = 0.0

        if flow.total_bytes >= self.thresholds.high_bytes_threshold:
            reasons.append(
                f"High data transfer volume detected: {flow.total_bytes} bytes"
            )
            score += 0.30

        if flow.packets >= self.thresholds.high_packet_threshold:
            reasons.append(
                f"Unusually high packet count detected: {flow.packets}"
            )
            score += 0.25

        if flow.bytes_per_second >= self.thresholds.high_rate_threshold:
            reasons.append(
                "Unusually high transfer rate detected: "
                f"{flow.bytes_per_second:.2f} bytes/second"
            )
            score += 0.25

        if flow.duration_seconds >= self.thresholds.long_duration_threshold:
            reasons.append(
                "Long-running connection detected: "
                f"{flow.duration_seconds:.2f} seconds"
            )
            score += 0.15

        if (
            flow.destination_port
            in self.thresholds.suspicious_destination_ports
        ):
            reasons.append(
                f"Traffic detected on monitored destination port "
                f"{flow.destination_port}"
            )
            score += 0.20

        score = min(score, 1.0)
        is_anomaly = bool(reasons)

        return AnomalyResult(
            flow=flow,
            is_anomaly=is_anomaly,
            anomaly_score=score,
            severity=self._severity_from_score(score),
            reason=(
                "; ".join(reasons)
                if reasons
                else "No suspicious rule-based behavior detected"
            ),
        )

    def analyze_many(
        self,
        flows: list[NetworkFlow],
    ) -> list[AnomalyResult]:
        """Analyze multiple network flows."""
        return [self.analyze(flow) for flow in flows]

    @staticmethod
    def _severity_from_score(score: float) -> str:
        """Convert an anomaly score into a SOC alert severity."""

        if score >= 0.80:
            return "CRITICAL"

        if score >= 0.60:
            return "HIGH"

        if score >= 0.40:
            return "MEDIUM"

        if score > 0:
            return "LOW"

        return "INFO"
