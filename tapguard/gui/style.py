"""Palette, severity colours, and the application stylesheet."""
from __future__ import annotations

COLORS = {
    "bg": "#0b0e13",
    "surface": "#141821",
    "table": "#10141b",
    "border": "#212631",
    "text": "#e6e8ec",
    "muted": "#7a808b",
    "accent": "#5b8cff",
}

ACCENT = COLORS["accent"]
TEXT = COLORS["text"]
MUTED = COLORS["muted"]
NEW_COLOR = "#3fb950"

# Desaturated, calmer severity hues.
SEVERITY_COLORS = {
    "Critical": "#f0564d",
    "High": "#f2944a",
    "Medium": "#e0b23c",
    "Low": "#5b8cff",
    "Info": "#6e7681",
}

STYLESHEET = """
QMainWindow, QWidget#root { background: #0b0e13; }
QWidget { color: #e6e8ec; font-size: 13px; }

QLabel#title { font-size: 17px; font-weight: 600; }
QLabel#subtitle { color: #7a808b; font-size: 12px; }

QFrame#card { background: #141821; border: 1px solid #212631; border-radius: 10px; }

QPushButton#primary {
    background: #5b8cff; color: #ffffff; border: none;
    padding: 8px 18px; border-radius: 8px; font-weight: 600;
}
QPushButton#primary:hover { background: #6f9bff; }
QPushButton#primary:disabled { background: #222835; color: #5a606b; }

QTableWidget {
    background: #10141b; border: 1px solid #212631; border-radius: 10px;
    gridline-color: transparent; alternate-background-color: #121722;
    selection-background-color: #1b2433; outline: 0;
}
QTableWidget::item { padding: 6px 10px; border: none; }
QTableWidget::item:selected { background: #1b2433; }
QHeaderView::section {
    background: #0e1218; color: #6b7178; padding: 8px 10px;
    border: none; border-bottom: 1px solid #212631; font-weight: 600; font-size: 11px;
}
QTableCornerButton::section { background: #0e1218; border: none; }

QTextBrowser#detail {
    background: #10141b; border: 1px solid #212631; border-radius: 10px; padding: 10px;
}

QSpinBox {
    background: #10141b; border: 1px solid #2b3240; border-radius: 7px;
    padding: 4px 6px; color: #e6e8ec;
}
QSpinBox::up-button, QSpinBox::down-button { width: 14px; border: none; background: transparent; }

QScrollBar:vertical { background: transparent; width: 10px; margin: 4px 2px; }
QScrollBar::handle:vertical { background: #2a313d; border-radius: 5px; min-height: 28px; }
QScrollBar::handle:vertical:hover { background: #343c4a; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: transparent; }
"""
