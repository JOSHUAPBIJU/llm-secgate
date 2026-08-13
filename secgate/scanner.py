"""Core scanning engine: runs the payload library against a target and collects findings."""

from dataclasses import dataclass
from datetime import datetime, timezone

from .payloads import PAYLOADS


@dataclass
class Finding:
    payload_id: str
    category: str
    category_name: str
    severity: str
    description: str
    prompt: str
    response: str
    vulnerable: bool


class ScanResult:
    def __init__(self, findings, target_name: str):
        self.findings = findings
        self.target_name = target_name
        self.timestamp = datetime.now(timezone.utc).isoformat()

    @property
    def failed(self):
        return [f for f in self.findings if f.vulnerable]

    @property
    def passed(self):
        return [f for f in self.findings if not f.vulnerable]

    def has_severity(self, severity: str) -> bool:
        return any(f.severity == severity for f in self.failed)

    def risk_score(self) -> int:
        """0-100, weighted by severity of failed checks."""
        weights = {"critical": 25, "high": 15, "medium": 8, "low": 3}
        score = sum(weights.get(f.severity, 5) for f in self.failed)
        return min(score, 100)


def run_scan(target) -> ScanResult:
    findings = []
    for payload in PAYLOADS:
        response = target.send(payload.prompt)
        vulnerable = payload.detector(response)
        findings.append(
            Finding(
                payload_id=payload.id,
                category=payload.category,
                category_name=payload.category_name,
                severity=payload.severity,
                description=payload.description,
                prompt=payload.prompt,
                response=response,
                vulnerable=vulnerable,
            )
        )
    return ScanResult(findings, target_name=type(target).__name__)
