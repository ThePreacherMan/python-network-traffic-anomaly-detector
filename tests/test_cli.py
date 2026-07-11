"""Tests for the command-line interface."""

import json
from pathlib import Path

from anomaly_detector.cli import main


def write_csv(tmp_path: Path) -> Path:
    """Create a temporary network traffic CSV file."""

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


def test_cli_prints_text_results(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    """The CLI should print readable traffic-analysis results."""

    file_path = write_csv(tmp_path)

    monkeypatch.setattr(
        "sys.argv",
        ["network-anomaly-detector", str(file_path)],
    )

    exit_code = main()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Result #1" in captured.out
    assert "Result #2" in captured.out
    assert "Severity Summary" in captured.out
    assert "CRITICAL: 1" in captured.out
    assert captured.err == ""


def test_cli_anomalies_only_filters_normal_traffic(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    """The anomalies-only option should exclude normal flows."""

    file_path = write_csv(tmp_path)

    monkeypatch.setattr(
        "sys.argv",
        [
            "network-anomaly-detector",
            str(file_path),
            "--anomalies-only",
        ],
    )

    exit_code = main()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Result #1" in captured.out
    assert "Result #2" not in captured.out
    assert "203.0.113.50:4444" in captured.out
    assert "8.8.8.8:53" not in captured.out


def test_cli_outputs_valid_json(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    """The JSON option should produce machine-readable output."""

    file_path = write_csv(tmp_path)

    monkeypatch.setattr(
        "sys.argv",
        [
            "network-anomaly-detector",
            str(file_path),
            "--json",
        ],
    )

    exit_code = main()
    captured = capsys.readouterr()
    results = json.loads(captured.out)

    assert exit_code == 0
    assert len(results) == 2
    assert results[0]["is_anomaly"] is False
    assert results[1]["is_anomaly"] is True
    assert results[1]["severity"] == "CRITICAL"


def test_cli_reports_missing_file(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    """The CLI should return an error for a missing traffic file."""

    missing_file = tmp_path / "missing.csv"

    monkeypatch.setattr(
        "sys.argv",
        ["network-anomaly-detector", str(missing_file)],
    )

    exit_code = main()
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert "Traffic data file not found" in captured.err
