from dataclasses import dataclass, field
from datetime import datetime, timezone


def timestamp(value):
    if isinstance(value, datetime): return value
    if not value: return datetime.min.replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(str(value).replace('Z', '+00:00')).replace(tzinfo=timezone.utc)


@dataclass
class Observation:
    evidence_id: str
    system_id: str
    resource_id: str
    category: str
    state: str
    observed_at: str
    available_at: str
    fields: dict = field(default_factory=dict)
    identity_keys: set = field(default_factory=set)
    scope: str = 'logical'
    locator: str = ''
    assertion: str = 'read'

    def eligible(self, audit_at):
        return max(timestamp(self.observed_at), timestamp(self.available_at)) <= timestamp(audit_at)


@dataclass
class AuditDecision:
    case_id: str
    status: str
    steps: list[dict]
    diagnostics: dict = field(default_factory=dict)

    @property
    def deletion_status(self): return self.status


class UnresolvedAudit(RuntimeError):
    def __init__(self, case_id, details):
        self.case_id = case_id
        self.details = details
        super().__init__(f'{case_id}: {details}')
