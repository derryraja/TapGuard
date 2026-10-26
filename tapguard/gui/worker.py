"""Run a scan off the UI thread so the window stays responsive."""
from __future__ import annotations

from PySide6.QtCore import QObject, QRunnable, Signal

from ..engine import DetectionEngine


class ScanSignals(QObject):
    finished = Signal(list)  # list[Finding]
    failed = Signal(str)


class ScanJob(QRunnable):
    def __init__(self, engine: DetectionEngine) -> None:
        super().__init__()
        self.engine = engine
        self.signals = ScanSignals()
        self.setAutoDelete(False)  # keep alive until the queued signal is delivered

    def run(self) -> None:
        try:
            self.signals.finished.emit(self.engine.run())
        except Exception as exc:  # noqa: BLE001
            self.signals.failed.emit(str(exc))
