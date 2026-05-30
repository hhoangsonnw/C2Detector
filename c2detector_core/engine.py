"""Detector registration and execution."""

from c2detector_core.config import AnalysisConfig
from c2detector_core.models import AnalysisResult, Finding


class DetectionRule:
    rule_id = "base"
    name = "Base rule"

    def evaluate(self, result: AnalysisResult, config: AnalysisConfig) -> list[Finding]:
        raise NotImplementedError


class DetectionEngine:
    def __init__(self) -> None:
        self.rules: list[DetectionRule] = []

    def register(self, rule: DetectionRule) -> None:
        self.rules.append(rule)

    def evaluate(self, result: AnalysisResult, config: AnalysisConfig) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self.rules:
            findings.extend(rule.evaluate(result, config))
        findings.sort(key=lambda item: (-item.score, item.first_seen, item.finding_id))
        return renumber_findings(findings)


def renumber_findings(findings: list[Finding]) -> list[Finding]:
    counters: dict[str, int] = {}
    for finding in findings:
        prefix = finding.finding_id.split("-", 1)[0]
        counters[prefix] = counters.get(prefix, 0) + 1
        finding.finding_id = f"{prefix}-{counters[prefix]:03d}"
        for flow in finding.suspicious_flows:
            flow.finding_id = finding.finding_id
    return findings
