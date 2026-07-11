"""High-level network traffic analysis service."""

from pathlib import Path

from anomaly_detector.loader import load_network_flows
from anomaly_detector.models import AnomalyResult, NetworkFlow
from anomaly_detector.rules import DetectionThresholds, RuleBasedDetector


class TrafficAnalyzer:
    """Coordinate traffic loading and rule-based anomaly analysis."""

    def __init__(
        self,
        thresholds: DetectionThresholds | None = None,
    ) -> None:
        """Initialize the traffic analyzer."""
        self.detector = RuleBasedDetector(thresholds)

    def analyze_flows(
        self,
        flows: list[NetworkFlow],
    ) -> list[AnomalyResult]:
        """Analyze a collection of network flows."""
        return self.detector.analyze_many(flows)

    def analyze_file(
        self,
        file_path: str | Path,
    ) -> list[AnomalyResult]:
        """Load and analyze network traffic from a CSV file."""
        flows = load_network_flows(file_path)
        return self.analyze_flows(flows)

    @staticmethod
    def anomalies_only(
        results: list[AnomalyResult],
    ) -> list[AnomalyResult]:
        """Return only results classified as anomalies."""
        return [result for result in results if result.is_anomaly]

    @staticmethod
    def severity_summary(
        results: list[AnomalyResult],
    ) -> dict[str, int]:
        """Return alert counts grouped by severity."""
        summary = {
            "INFO": 0,
            "LOW": 0,
            "MEDIUM": 0,
            "HIGH": 0,
            "CRITICAL": 0,
        }

        for result in results:
            severity = result.severity.upper()
            summary[severity] = summary.get(severity, 0) + 1

        return summary
