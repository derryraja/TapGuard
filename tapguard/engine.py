"""Detection engine: selects the platform's detectors, runs them, aggregates.

The GUI (or any other front-end) talks to this class only - it never imports
detectors directly. That keeps the front-end decoupled from platform details.
"""
from __future__ import annotations

import platform
from typing import Callable

from .models import Finding, Severity

Detector = Callable[[], list[Finding]]


class DetectionEngine:
    def __init__(self) -> None:
        self._detectors: list[tuple[str, Detector]] = self._load_detectors()

    def _load_detectors(self) -> list[tuple[str, Detector]]:
        system = platform.system()
        if system == "Darwin":
            from .detectors.macos import event_taps, permissions, persistence

            return [
                ("Event taps", event_taps.scan),
                ("Input permissions", permissions.scan),
                ("Persistence", persistence.scan),
            ]
        # Windows support is on the roadmap - see README.
        raise RuntimeError(
            f"Unsupported platform: {system!r}. This release supports macOS only."
        )

    def run(self) -> list[Finding]:
        """Run every detector. A failing detector is reported, not fatal."""
        findings: list[Finding] = []
        for name, scan in self._detectors:
            try:
                findings.extend(scan())
            except Exception as exc:  # noqa: BLE001 - surface, don't crash
                findings.append(
                    Finding(
                        title=f"{name} detector could not run",
                        severity=Severity.INFO,
                        detector=name,
                        description=str(exc),
                        recommendation="Check that the required macOS permissions are granted.",
                    )
                )
        findings.sort(key=lambda f: f.severity.rank, reverse=True)
        return findings

    @staticmethod
    def risk_score(findings: list[Finding]) -> int:
        """A simple 0-100 headline score driven by the worst finding."""
        weights = {
            Severity.CRITICAL: 100,
            Severity.HIGH: 75,
            Severity.MEDIUM: 45,
            Severity.LOW: 20,
            Severity.INFO: 0,
        }
        if not findings:
            return 0
        return max(weights[f.severity] for f in findings)
