import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from secgate.scanner import run_scan
from secgate.target import MockVulnerableLLM


def test_scan_runs_all_payloads():
    result = run_scan(MockVulnerableLLM())
    assert len(result.findings) > 0


def test_mock_target_is_detected_as_vulnerable():
    """The mock target is deliberately insecure, so the scanner should catch it."""
    result = run_scan(MockVulnerableLLM())
    assert len(result.failed) > 0
    assert result.has_severity("critical")


def test_risk_score_is_bounded():
    result = run_scan(MockVulnerableLLM())
    assert 0 <= result.risk_score() <= 100


def test_gate_fails_on_critical_findings():
    result = run_scan(MockVulnerableLLM())
    assert result.has_severity("critical") is True
