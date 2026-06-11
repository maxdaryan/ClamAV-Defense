#!/usr/bin/env python3
"""
Open Clam Scanner (Windows Edition) — A beginner-friendly ClamAV GUI.

Requirements:
    pip install PyQt6
    Install ClamAV for Windows (https://www.clamav.net/downloads)
    Ensure clamscan.exe and freshclam.exe are in your PATH or in C:\Program Files\ClamAV

Usage:
    python open_clam_scanner_windows.py
"""

import sys
import os
import re
import shutil
import platform
import subprocess
import time
import datetime
from pathlib import Path

from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QPropertyAnimation,
    QEasingCurve, pyqtProperty,
)
from PyQt6.QtGui import (
    QFont, QColor, QPalette, QPainter, QBrush, QIcon,
)
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QPlainTextEdit, QFileDialog, QMessageBox,
    QFrame, QProgressBar, QGraphicsDropShadowEffect,
    QGridLayout,
)

# ──────────────────────────────────────────────────────────────────────────────
# Constants & Paths
# ──────────────────────────────────────────────────────────────────────────────
APP_TITLE = "Open Clam Scanner - Windows"
APP_VERSION = "1.0.0"
HOME_DIR = Path.home()
LOGS_DIR = Path(__file__).resolve().parent / "logs"
QUARANTINE_DIR = Path(__file__).resolve().parent / "quarantine"

QUICK_SCAN_DIRS = [
    HOME_DIR / "Downloads",
    HOME_DIR / "Desktop",
    HOME_DIR / "Documents",
]

def find_binary(name: str) -> str | None:
    # Check PATH first
    found = shutil.which(name)
    if found: return found
    # Check common Windows paths
    candidates = [
        Path("C:/Program Files/ClamAV") / f"{name}.exe",
        Path("C:/Program Files (x86)/ClamAV") / f"{name}.exe",
    ]
    for c in candidates:
        if c.exists(): return str(c)
    return None

def get_clamav_version(clamscan_path: str) -> str:
    try:
        result = subprocess.run(
            [clamscan_path, "--version"],
            capture_output=True, text=True, timeout=10, shell=True
        )
        return result.stdout.strip() or result.stderr.strip()
    except Exception as exc:
        return f"Error: {exc}"

def check_virus_db_exists() -> bool:
    clamscan = find_binary("clamscan")
    candidates = []
    if clamscan:
        candidates.append(Path(clamscan).parent / "database")
    candidates.append(Path("C:/ProgramData/ClamAV/db"))
    
    db_names = ("main.cvd", "main.cld", "daily.cvd", "daily.cld")
    for d in candidates:
        if d.is_dir():
            for name in db_names:
                if (d / name).exists():
                    return True
    return False

class ScanWorker(QThread):
    output_line = pyqtSignal(str)
    finished_sig = pyqtSignal(int, float)

    def __init__(self, command: list[str], parent=None):
        super().__init__(parent)
        self.command = command
        self._process = None
        self._stop_requested = False

    def request_stop(self):
        self._stop_requested = True
        if self._process:
            self._process.terminate()

    def run(self):
        start = time.time()
        try:
            self._process = subprocess.Popen(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                shell=True
            )
            for line in iter(self._process.stdout.readline, ""):
                if self._stop_requested:
                    break
                self.output_line.emit(line.rstrip("\n"))
            self._process.stdout.close()
            self._process.wait()
            elapsed = time.time() - start
            self.finished_sig.emit(self._process.returncode, elapsed)
        except Exception as exc:
            self.output_line.emit(f"Error: {exc}")
            self.finished_sig.emit(-1, time.time() - start)

class StatusDot(QWidget):
    def __init__(self, color: str = "#4ade80", size: int = 14, parent=None):
        super().__init__(parent)
        self._color = QColor(color)
        self._size = size
        self._opacity = 1.0
        self.setFixedSize(size + 4, size + 4)
        self._anim = QPropertyAnimation(self, b"opacity")
        self._anim.setDuration(1200)
        self._anim.setStartValue(1.0)
        self._anim.setEndValue(0.35)
        self._anim.setEasingCurve(QEasingCurve.Type.InOutSine)
        self._anim.setLoopCount(-1)

    def _get_opacity(self): return self._opacity
    def _set_opacity(self, val):
        self._opacity = val
        self.update()

    opacity = pyqtProperty(float, _get_opacity, _set_opacity)

    def set_color(self, color: str):
        self._color = QColor(color)
        self.update()

    def start_pulse(self): self._anim.start()
    def stop_pulse(self):
        self._anim.stop()
        self._opacity = 1.0
        self.update()

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        c = QColor(self._color)
        c.setAlphaF(self._opacity)
        painter.setBrush(QBrush(c))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(2, 2, self._size, self._size)
        painter.end()

class AnimatedButton(QPushButton):
    def __init__(self, text: str, accent: str = "#3a3a3c", parent=None):
        super().__init__(text, parent)
        self._accent = QColor(accent)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setGraphicsEffect(self._make_shadow(8, 0, 2, QColor(0, 0, 0, 100)))

    @staticmethod
    def _make_shadow(blur: int, x_off: int, y_off: int, color: QColor) -> QGraphicsDropShadowEffect:
        effect = QGraphicsDropShadowEffect()
        effect.setBlurRadius(blur)
        effect.setOffset(x_off, y_off)
        effect.setColor(color)
        return effect

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self._clamscan_path = find_binary("clamscan")
        self._freshclam_path = find_binary("freshclam")
        self._worker = None
        self._scan_running = False

        LOGS_DIR.mkdir(exist_ok=True)
        QUARANTINE_DIR.mkdir(exist_ok=True)

        self.setWindowTitle(APP_TITLE)
        self.setWindowIcon(QIcon(str(Path(__file__).resolve().parent / "calmqt.png")))
        self.setMinimumSize(920, 750)
        self.resize(1060, 850)
        self._build_ui()
        self._apply_styles()
        self._refresh_status()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)
        root_layout.setContentsMargins(32, 24, 32, 24)
        root_layout.setSpacing(20)

        header = QHBoxLayout()
        title_container = QVBoxLayout()
        title_lbl = QLabel("ClamAV Defense")
        title_lbl.setObjectName("appTitle")
        subtitle_lbl = QLabel("Intelligent security for Windows")
        subtitle_lbl.setObjectName("appSubtitle")
        title_container.addWidget(title_lbl)
        title_container.addWidget(subtitle_lbl)
        header.addLayout(title_container)
        root_layout.addLayout(header)

        self.status_card = QFrame()
        self.status_card.setObjectName("statusCard")
        sc_outer = QVBoxLayout(self.status_card)
        sc_top = QHBoxLayout()
        self.status_dot = StatusDot("#34c759", 12)
        sc_top.addWidget(self.status_dot)
        self.status_label = QLabel("Analyzing...")
        self.status_label.setObjectName("statusLabel")
        sc_top.addWidget(self.status_label)
        sc_outer.addLayout(sc_top)
        root_layout.addWidget(self.status_card)

        btn_grid = QGridLayout()
        self.btn_update = self._make_button("Update Definitions", "#007aff", self._on_update)
        self.btn_quick  = self._make_button("Quick Scan",        "#007aff", self._on_quick)
        btn_grid.addWidget(self.btn_update, 0, 0)
        btn_grid.addWidget(self.btn_quick,  0, 1)
        root_layout.addLayout(btn_grid)

        self.console = QPlainTextEdit()
        self.console.setObjectName("console")
        self.console.setReadOnly(True)
        root_layout.addWidget(self.console, stretch=1)

        self.summary_label = QLabel("Ready.")
        root_layout.addWidget(self.summary_label)

    @staticmethod
    def _make_button(text: str, accent: str, slot) -> AnimatedButton:
        btn = AnimatedButton(text, accent)
        btn.setMinimumHeight(48)
        btn.clicked.connect(slot)
        btn.setProperty("accent", accent)
        return btn

    def _refresh_status(self):
        if self._clamscan_path:
            self.status_label.setText("Protection Shield Active")
            self.status_dot.set_color("#34c759")
        else:
            self.status_label.setText("ClamAV Not Found")
            self.status_dot.set_color("#ff3b30")

    def _log(self, text: str):
        self.console.appendPlainText(text)

    def _start_command(self, command: list[str]):
        if self._scan_running: return
        self._scan_running = True
        self.console.clear()
        self._worker = ScanWorker(command, self)
        self._worker.output_line.connect(self._log)
        self._worker.finished_sig.connect(self._on_finished)
        self._worker.start()

    def _on_finished(self, code, elapsed):
        self._scan_running = False
        self.summary_label.setText(f"Finished in {elapsed:.1f}s")

    def _on_update(self):
        if self._freshclam_path: self._start_command([self._freshclam_path])

    def _on_quick(self):
        if self._clamscan_path: self._start_command([self._clamscan_path, "-r", str(HOME_DIR / "Downloads")])

    def _apply_styles(self):
        self.setStyleSheet("""
        QMainWindow, QWidget { background-color: #0c0c0e; color: #f5f5f7; font-family: "Segoe UI", sans-serif; }
        #appTitle { font-size: 24px; font-weight: bold; }
        #statusCard { background-color: #1c1c1e; border-radius: 12px; border: 1px solid #38383a; }
        QPushButton { background-color: #2c2c2e; border-radius: 8px; padding: 10px; }
        #console { background-color: #000000; color: #30d158; font-family: "Consolas", monospace; }
        """)

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
