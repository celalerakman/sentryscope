"""Immutable analysis records shared by workers, persistence and reporters."""
from dataclasses import asdict, dataclass, field, replace
import hashlib
import json
from typing import Literal

Severity = Literal['critical', 'high', 'medium', 'low']
RANK = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    cwe: str
    description: str
    remediation: str


@dataclass(frozen=True)
class TraceStep:
    line: int
    column: int
    label: str


@dataclass(frozen=True)
class Finding:
    rule_id: str
    path: str
    line: int
    column: int
    end_line: int
    scope: str
    message: str
    severity: Severity
    confidence: str
    fingerprint: str
    trace: tuple[TraceStep, ...] = ()
    suppressed: bool = False
    suppression_reason: str = ''

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        data = dict(data)
        data['trace'] = tuple(TraceStep(**step) for step in data.get('trace', []))
        return cls(**data)


@dataclass(frozen=True)
class Diagnostic:
    path: str
    category: str
    message: str


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    duration_seconds: float = 0.0
    policy_digest: str = ''

    def to_dict(self):
        return {'schema_version': 1, **asdict(self)}

    @property
    def complete(self):
        return not self.diagnostics

    def fails(self, threshold):
        if threshold not in RANK:
            raise ValueError('Unknown severity threshold')
        return any(not f.suppressed and RANK[f.severity] >= RANK[threshold] for f in self.findings)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def finding_order(finding):
    return (finding.path, finding.line, finding.column, finding.rule_id, finding.fingerprint)
