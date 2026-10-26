"""Shared data types for findings and severity."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(Enum):
    """Ordered severity levels. ``rank`` is used for sorting and scoring."""

    INFO = ("Info", 0)
    LOW = ("Low", 1)
    MEDIUM = ("Medium", 2)
    HIGH = ("High", 3)
    CRITICAL = ("Critical", 4)

    def __init__(self, label: str, rank: int) -> None:
        self.label = label
        self.rank = rank


@dataclass
class Finding:
    """A single thing the scan surfaced, for a human to review."""

    title: str
    severity: Severity
    detector: str
    description: str
    process_name: Optional[str] = None
    pid: Optional[int] = None
    recommendation: Optional[str] = None
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def signature(self) -> tuple:
        """A stable identity used to tell whether a finding is newly appeared."""
        ident = (
            self.details.get("plist")
            or self.details.get("client")
            or self.details.get("executable")
            or self.details.get("login_item")
            or ""
        )
        return (self.detector, self.title, self.process_name, self.pid, ident)
