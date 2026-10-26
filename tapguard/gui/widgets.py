"""Custom widgets: a painted toggle switch."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import QCheckBox

from .style import ACCENT


class ToggleSwitch(QCheckBox):
    """A checkbox drawn as a compact iOS-style toggle."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setCursor(Qt.PointingHandCursor)
        self.setFixedSize(42, 24)

    def hitButton(self, pos) -> bool:
        return self.contentsRect().contains(pos)

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(Qt.NoPen)
        rect = self.rect().adjusted(1, 1, -1, -1)
        track = QColor(ACCENT) if self.isChecked() else QColor("#2a313d")
        painter.setBrush(track)
        radius = rect.height() / 2
        painter.drawRoundedRect(rect, radius, radius)
        diameter = rect.height() - 6
        x = rect.right() - diameter - 3 if self.isChecked() else rect.left() + 3
        painter.setBrush(QColor("#ffffff"))
        painter.drawEllipse(int(x), int(rect.top() + 3), int(diameter), int(diameter))
        painter.end()
