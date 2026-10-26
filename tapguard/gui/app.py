"""TapGuard - PySide6 front-end with snapshot + live monitoring."""
from __future__ import annotations

import html
import sys
from datetime import datetime

from PySide6.QtCore import Qt, QThreadPool, QTimer
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMainWindow,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from ..engine import DetectionEngine
from ..models import Finding
from .style import ACCENT, MUTED, NEW_COLOR, SEVERITY_COLORS, STYLESHEET, TEXT
from .widgets import ToggleSwitch
from .worker import ScanJob

COLUMNS = ["", "Severity", "Finding", "Process", "PID", "Detector"]


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.engine = DetectionEngine()
        self.pool = QThreadPool()
        self.pool.setMaxThreadCount(1)
        self._busy = False
        self._scanned_once = False
        self._prev_keys: set = set()
        self._findings: list[Finding] = []
        self._job = None

        self.setWindowTitle("TapGuard")
        self.resize(1040, 680)
        self._build_ui()
        self.setStyleSheet(STYLESHEET)

        self.monitor_timer = QTimer(self)
        self.monitor_timer.timeout.connect(self._tick)

    # ---------------------------------------------------------------- UI
    def _build_ui(self) -> None:
        root = QWidget()
        root.setObjectName("root")
        outer = QVBoxLayout(root)
        outer.setContentsMargins(20, 18, 20, 16)
        outer.setSpacing(14)

        title = QLabel("TapGuard")
        title.setObjectName("title")
        subtitle = QLabel("Read-only scan for macOS keyboard surveillance")
        subtitle.setObjectName("subtitle")
        header = QVBoxLayout()
        header.setSpacing(2)
        header.addWidget(title)
        header.addWidget(subtitle)
        outer.addLayout(header)

        controls = QFrame()
        controls.setObjectName("card")
        crow = QHBoxLayout(controls)
        crow.setContentsMargins(14, 10, 14, 10)
        crow.setSpacing(12)

        self.scan_btn = QPushButton("Scan now")
        self.scan_btn.setObjectName("primary")
        self.scan_btn.clicked.connect(lambda: self._start_scan())
        crow.addWidget(self.scan_btn)
        crow.addSpacing(10)

        monitor_label = QLabel("Monitor")
        self.monitor_switch = ToggleSwitch()
        self.monitor_switch.toggled.connect(self._toggle_monitor)
        crow.addWidget(monitor_label)
        crow.addWidget(self.monitor_switch)

        every = QLabel("every")
        every.setObjectName("subtitle")
        self.interval = QSpinBox()
        self.interval.setRange(2, 120)
        self.interval.setValue(5)
        self.interval.setSuffix(" s")
        self.interval.valueChanged.connect(self._interval_changed)
        crow.addWidget(every)
        crow.addWidget(self.interval)

        crow.addStretch(1)
        self.last_scan = QLabel("Not scanned yet")
        self.last_scan.setObjectName("subtitle")
        crow.addWidget(self.last_scan)
        outer.addWidget(controls)

        self.summary_layout = QHBoxLayout()
        self.summary_layout.setSpacing(14)
        self.summary_layout.setContentsMargins(4, 0, 4, 0)
        self.summary_layout.addStretch(1)
        summary_wrap = QWidget()
        summary_wrap.setLayout(self.summary_layout)
        outer.addWidget(summary_wrap)

        splitter = QSplitter(Qt.Vertical)
        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(40)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setShowGrid(False)
        head = self.table.horizontalHeader()
        head.setSectionResizeMode(0, QHeaderView.Fixed)
        head.setSectionResizeMode(1, QHeaderView.Fixed)
        head.setSectionResizeMode(2, QHeaderView.Stretch)
        head.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        head.setSectionResizeMode(4, QHeaderView.Fixed)
        head.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.table.setColumnWidth(0, 52)
        self.table.setColumnWidth(1, 108)
        self.table.setColumnWidth(4, 68)
        head.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.table.itemSelectionChanged.connect(self._selection_changed)
        splitter.addWidget(self.table)

        self.detail = QTextBrowser()
        self.detail.setObjectName("detail")
        self.detail.setHtml(self._placeholder_html())
        splitter.addWidget(self.detail)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        splitter.setSizes([400, 210])
        outer.addWidget(splitter, 1)

        self.setCentralWidget(root)

    # ---------------------------------------------------------- scanning
    def _start_scan(self) -> None:
        if self._busy:
            return
        self._busy = True
        self.scan_btn.setEnabled(False)
        self.last_scan.setText("Scanning…")
        job = self._job = ScanJob(self.engine)
        job.signals.finished.connect(self._on_results)
        job.signals.failed.connect(self._on_failed)
        self.pool.start(job)

    def _tick(self) -> None:
        if not self._busy:
            self._start_scan()

    def _toggle_monitor(self, on: bool) -> None:
        if on:
            self.monitor_timer.start(self.interval.value() * 1000)
            self._start_scan()
        else:
            self.monitor_timer.stop()

    def _interval_changed(self, value: int) -> None:
        if self.monitor_timer.isActive():
            self.monitor_timer.start(value * 1000)

    def _on_failed(self, message: str) -> None:
        self._busy = False
        self.scan_btn.setEnabled(True)
        self.last_scan.setText("Scan failed")
        self.detail.setHtml(f"<p style='color:#f0564d'>Scan failed: {html.escape(message)}</p>")

    def _on_results(self, findings: list) -> None:
        self._busy = False
        self.scan_btn.setEnabled(True)
        keys = {f.signature for f in findings}
        new_keys = (keys - self._prev_keys) if self._scanned_once else set()
        selected_sig = self._selected_signature()
        self._findings = findings
        self._populate(findings, new_keys)
        self._update_summary(findings, len(new_keys))
        self.last_scan.setText("Last scan " + datetime.now().strftime("%H:%M:%S"))
        self._prev_keys = keys
        self._scanned_once = True
        self._restore_selection(selected_sig)

    # ------------------------------------------------------------ table
    def _populate(self, findings: list, new_keys: set) -> None:
        self.table.setRowCount(len(findings))
        for row, finding in enumerate(findings):
            is_new = finding.signature in new_keys

            new_item = QTableWidgetItem("NEW" if is_new else "")
            new_item.setTextAlignment(Qt.AlignCenter)
            if is_new:
                new_item.setForeground(QBrush(QColor(NEW_COLOR)))
                font = new_item.font()
                font.setBold(True)
                font.setPointSizeF(max(font.pointSizeF() - 1.5, 8.0))
                new_item.setFont(font)
            self.table.setItem(row, 0, new_item)

            sev_item = QTableWidgetItem("●  " + finding.severity.label)
            sev_item.setForeground(QBrush(QColor(SEVERITY_COLORS[finding.severity.label])))
            self.table.setItem(row, 1, sev_item)

            self._set_text(row, 2, finding.title, bold=is_new)
            self._set_text(row, 3, finding.process_name or "—")
            self._set_text(row, 4, str(finding.pid) if finding.pid is not None else "—")
            self._set_text(row, 5, finding.detector, muted=True)

    def _set_text(self, row: int, col: int, text: str, bold: bool = False,
                  center: bool = False, muted: bool = False) -> None:
        item = QTableWidgetItem(text)
        if bold:
            font = item.font()
            font.setBold(True)
            item.setFont(font)
        if center:
            item.setTextAlignment(Qt.AlignCenter)
        if muted:
            item.setForeground(QBrush(QColor(MUTED)))
        self.table.setItem(row, col, item)

    def _selected_signature(self):
        row = self.table.currentRow()
        if 0 <= row < len(self._findings):
            return self._findings[row].signature
        return None

    def _restore_selection(self, signature) -> None:
        if not self._findings:
            self.detail.setHtml(self._empty_html())
            return
        target = 0
        if signature is not None:
            for index, finding in enumerate(self._findings):
                if finding.signature == signature:
                    target = index
                    break
        self.table.selectRow(target)

    def _selection_changed(self) -> None:
        row = self.table.currentRow()
        if 0 <= row < len(self._findings):
            self.detail.setHtml(self._detail_html(self._findings[row]))

    # ---------------------------------------------------------- summary
    def _update_summary(self, findings: list, new_count: int) -> None:
        self._clear_layout(self.summary_layout)
        score = DetectionEngine.risk_score(findings)
        band, word = self._risk_band(score)
        risk = QLabel(
            f"<span style='color:{MUTED};font-size:12px'>Risk</span>&nbsp;&nbsp;"
            f"<span style='color:{band};font-size:20px;font-weight:700'>{score}</span>"
            f"<span style='color:{MUTED};font-size:12px'>/100 &nbsp;·&nbsp; {word}</span>"
        )
        self.summary_layout.addWidget(risk)

        counts: dict[str, int] = {}
        for finding in findings:
            counts[finding.severity.label] = counts.get(finding.severity.label, 0) + 1
        for label in ("Critical", "High", "Medium", "Low", "Info"):
            if counts.get(label):
                self.summary_layout.addWidget(
                    self._count_label(SEVERITY_COLORS[label], counts[label], label)
                )
        if new_count:
            self.summary_layout.addWidget(self._count_label(NEW_COLOR, new_count, "new"))
        self.summary_layout.addStretch(1)

    def _count_label(self, color: str, count: int, label: str) -> QLabel:
        return QLabel(
            f"<span style='color:{color}'>●</span>&nbsp;"
            f"<span style='color:{TEXT}'>{count}</span>&nbsp;"
            f"<span style='color:{MUTED}'>{html.escape(label)}</span>"
        )

    @staticmethod
    def _risk_band(score: int):
        if score == 0:
            return (MUTED, "Clear")
        if score < 45:
            return (ACCENT, "Low")
        if score < 75:
            return ("#f2944a", "Elevated")
        return ("#f0564d", "High")

    def _clear_layout(self, layout) -> None:
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

    # ------------------------------------------------------------ detail
    def _detail_html(self, finding: Finding) -> str:
        color = SEVERITY_COLORS.get(finding.severity.label, "#6e7681")
        rows = "".join(
            f"<tr><td style='color:#7a808b;padding:3px 14px 3px 0;vertical-align:top'>{html.escape(str(k))}</td>"
            f"<td style='color:#e6e8ec;padding:3px 0'>{html.escape(str(v))}</td></tr>"
            for k, v in finding.details.items()
        )
        rec = ""
        if finding.recommendation:
            rec = (
                "<p style='margin:12px 0 0'><b style='color:#e6e8ec'>Recommended</b><br>"
                f"<span style='color:#aab1bd'>{html.escape(finding.recommendation)}</span></p>"
            )
        return f"""
        <div>
          <span style='color:{color};font-size:11px;font-weight:700;letter-spacing:1px'>{finding.severity.label.upper()}</span>
          <span style='color:#7a808b;font-size:12px'>&nbsp;&nbsp;·&nbsp;&nbsp;{html.escape(finding.detector)}</span>
          <div style='color:#e6e8ec;font-size:15px;font-weight:600;margin:8px 0 4px'>{html.escape(finding.title)}</div>
          <p style='color:#c0c6d0;margin:0'>{html.escape(finding.description)}</p>
          {rec}
          <table style='margin-top:14px;font-size:12px;border-collapse:collapse'>{rows}</table>
        </div>
        """

    def _placeholder_html(self) -> str:
        return "<p style='color:#7a808b'>Run a scan, then select a finding to see the details.</p>"

    def _empty_html(self) -> str:
        return ("<p style='color:#3fb950'>No findings. Nothing this scan can see is "
                "intercepting keyboard input.</p>")


def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("TapGuard")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
