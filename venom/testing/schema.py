"""
Structured schemas for test cases and findings (matches the CIPHER prompt).
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class VulnClass(str, Enum):
    STATE_BYPASS = "STATE_BYPASS"
    SEQUENCE_VIOLATION = "SEQUENCE_VIOLATION"
    BOLA_IDOR = "BOLA_IDOR"
    RACE_CONDITION = "RACE_CONDITION"
    PARAM_POLLUTION = "PARAM_POLLUTION"
    TYPE_CONFUSION = "TYPE_CONFUSION"
    PRIV_ESCALATION = "PRIV_ESCALATION"
    MASS_ASSIGNMENT = "MASS_ASSIGNMENT"
    ECONOMIC_ABUSE = "ECONOMIC_ABUSE"
    FAITH_BASED_RULE = "FAITH_BASED_RULE"


class Verdict(str, Enum):
    NOT_RUN = "NOT_RUN"
    CONFIRMED_EXPLOIT = "CONFIRMED_EXPLOIT"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    ENVIRONMENTAL_ERROR = "ENVIRONMENTAL_ERROR"


@dataclass
class TestStep:
    __test__ = False  # not a pytest test class
    step: int
    description: str
    method: str
    path: str
    body: dict[str, Any] | None = None      # JSON body (API mode)
    form: dict[str, Any] | None = None      # form-encoded body (web-app mode)
    query: dict[str, Any] | None = None
    headers: dict[str, str] | None = None
    identity: str | None = None             # which authenticated identity to use
    role: str | None = None                 # legacy alias for identity
    expected_status: int | None = None
    extract: dict[str, str] = field(default_factory=dict)        # var -> JSONPath ($.id)
    extract_regex: dict[str, str] = field(default_factory=dict)  # var -> regex (group 1) on HTML
    success_condition: str | None = None    # expr over: status, body, text, vars, deltas
    concurrency: int = 1                    # >1 => fire N copies concurrently (race)
    rate_limited: bool = True               # set False for a true concurrency burst
    follow_redirects: bool = False          # web flows often 302 to a result page
    destructive: bool = False

    # Filled at runtime
    actual_status: int | None = None
    response_excerpt: str | None = None
    request_summary: str | None = None      # method + resolved path (evidence)

    @property
    def who(self) -> str | None:
        return self.identity or self.role

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TestCase:
    __test__ = False  # not a pytest test class
    test_id: str
    vulnerability_class: VulnClass
    hypothesis: str
    risk_rating: Severity
    business_impact: str = ""
    cvss_estimate: str = ""
    affected_endpoint: str = ""
    preconditions: list[str] = field(default_factory=list)
    setup_steps: list[TestStep] = field(default_factory=list)   # provision prerequisites
    steps: list[TestStep] = field(default_factory=list)
    state_probe: TestStep | None = None     # GET run before+after to measure deltas
    cleanup_steps: list[TestStep] = field(default_factory=list)
    rag_source: str = ""
    rag_refs: list[str] = field(default_factory=list)   # retrieved corpus references
    origin: str = "playbook"                # "playbook" | "llm" | "codegen"

    # Filled at runtime
    verdict: Verdict = Verdict.NOT_RUN
    notes: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["vulnerability_class"] = self.vulnerability_class.value
        d["risk_rating"] = self.risk_rating.value
        d["verdict"] = self.verdict.value
        return d


@dataclass
class Finding:
    finding_id: str
    title: str
    severity: Severity
    vulnerability_class: VulnClass
    affected_endpoint: str
    business_impact: str
    reproduction_steps: list[dict] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    cvss_vector: str = ""
    remediation: dict[str, str] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    source_test_id: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["vulnerability_class"] = self.vulnerability_class.value
        return d
