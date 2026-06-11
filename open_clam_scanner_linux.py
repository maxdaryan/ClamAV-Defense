#!/usr/bin/env python3
"""
Open Clam Scanner (Linux Edition) — A beginner-friendly ClamAV GUI.

Requirements:
    pip install PyQt6
    sudo apt install clamav clamav-daemon  (Debian/Ubuntu)
    sudo dnf install clamav clamav-update  (Fedora)
    sudo pacman -S clamav                  (Arch)

Usage:
    python open_clam_scanner_linux.py
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
APP_TITLE = "Open Clam Scanner - Linux"
APP_VERSION = "1.0.0"
HOME_DIR = Path.home()
LOGS_DIR = Path(__file__).resolve().parent / "logs"
QUARANTINE_DIR = Path(__file__).resolve().parent / "quarantine"

QUICK_SCAN_DIRS = [
    HOME_DIR / "Downloads",
    HOME_DIR / "Desktop",
    HOME_DIR / "Documents",
    Path("/tmp"),
]

def find_binary(name: str) -> str | None:
    return shutil.which(name)

def get_clamav_version(clamscan_path: str) -> str:
    try:
        result = subprocess.run(
            [clamscan_path, "--version"],
            capture_output=True, text=True, timeout=10,
        )
        return result.stdout.strip() or result.stderr.strip()
    except Exception as exc:
        return f"Error: {exc}"

def check_virus_db_exists() -> bool:
    candidates = [
        Path("/var/lib/clamav"),
        Path("/usr/local/share/clamav"),
        Path.home() / ".clamav",
    ]
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
        self._process: subprocess.Popen | None = None
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
            )
            for line in iter(self._process.stdout.readline, ""):
                if self._stop_requested:
                    break
                self.output_line.emit(line.rstrip("\n"))
            self._process.stdout.close()
            self._process.wait()
            elapsed = time.time() - start
            self.finished_sig.emit(self._process.returncode, elapsed)
        except FileNotFoundError:
            self.output_line.emit("Command not found. Is ClamAV installed? Try 'sudo apt install clamav'.")
            self.finished_sig.emit(-1, time.time() - start)
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

    def enterEvent(self, event):
        self.setGraphicsEffect(self._make_shadow(15, 0, 4, QColor(0, 0, 0, 150)))
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.setGraphicsEffect(self._make_shadow(8, 0, 2, QColor(0, 0, 0, 100)))
        super().leaveEvent(event)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self._clamscan_path = find_binary("clamscan")
        self._freshclam_path = find_binary("freshclam")
        self._worker = None
        self._current_log_path = None
        self._log_buffer = []
        self._scan_running = False
        self._infected_files = []

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
        subtitle_lbl = QLabel("Intelligent security for your Linux ecosystem")
        subtitle_lbl.setObjectName("appSubtitle")
        title_container.addWidget(title_lbl)
        title_container.addWidget(subtitle_lbl)
        header.addLayout(title_container)
        
        header.addStretch()
        ver_lbl = QLabel(f"Version {APP_VERSION}")
        ver_lbl.setObjectName("versionLabel")
        header.addWidget(ver_lbl, alignment=Qt.AlignmentFlag.AlignTop)
        root_layout.addLayout(header)

        self.status_card = QFrame()
        self.status_card.setObjectName("statusCard")
        sc_outer = QVBoxLayout(self.status_card)
        sc_outer.setContentsMargins(24, 20, 24, 20)
        sc_outer.setSpacing(10)

        sc_top = QHBoxLayout()
        sc_top.setSpacing(12)
        self.status_dot = StatusDot("#34c759", 12)
        sc_top.addWidget(self.status_dot, alignment=Qt.AlignmentFlag.AlignTop)

        status_text_container = QVBoxLayout()
        status_text_container.setSpacing(2)
        self.status_label = QLabel("Analyzing...")
        self.status_label.setObjectName("statusLabel")
        self.status_desc = QLabel("Verifying protection status.")
        self.status_desc.setObjectName("statusDesc")
        status_text_container.addWidget(self.status_label)
        status_text_container.addWidget(self.status_desc)
        sc_top.addLayout(status_text_container, stretch=1)
        sc_outer.addLayout(sc_top)

        sc_bottom = QHBoxLayout()
        self.version_label = QLabel("")
        self.version_label.setObjectName("versionInfo")
        sc_bottom.addWidget(self.version_label)
        sc_outer.addLayout(sc_bottom)
        root_layout.addWidget(self.status_card)

        btn_grid = QGridLayout()
        self.btn_update = self._make_button("Refresh Defense Intel", "#007aff", self._on_update_definitions)
        self.btn_quick  = self._make_button("Swift Analysis",        "#007aff", self._on_quick_scan)
        btn_grid.addWidget(self.btn_update, 0, 0)
        btn_grid.addWidget(self.btn_quick,  0, 1)

        self.btn_file   = self._make_button("Inspect File",         "#007aff", self._on_scan_file)
        self.btn_folder = self._make_button("Scan Directory",       "#007aff", self._on_scan_folder)
        btn_grid.addWidget(self.btn_file,   1, 0)
        btn_grid.addWidget(self.btn_folder, 1, 1)

        self.btn_home   = self._make_button("Deep System Inspection", "#007aff", self._on_full_home_scan)
        self.btn_stop   = self._make_button("Abort Operation",         "#ff3b30", self._on_stop_scan)
        self.btn_stop.setEnabled(False)
        btn_grid.addWidget(self.btn_home, 2, 0)
        btn_grid.addWidget(self.btn_stop, 2, 1)

        self.btn_logs       = self._make_button("Review Audit Logs",    "#8e8e93", self._on_open_logs)
        self.btn_quarantine = self._make_button("Isolate Detected Threats",  "#ff3b30", self._on_quarantine)
        self.btn_quarantine.setEnabled(False)
        btn_grid.addWidget(self.btn_logs,       3, 0)
        btn_grid.addWidget(self.btn_quarantine, 3, 1)
        root_layout.addLayout(btn_grid)

        self.console = QPlainTextEdit()
        self.console.setObjectName("console")
        self.console.setReadOnly(True)
        root_layout.addWidget(self.console, stretch=1)

        self.summary_frame = QFrame()
        self.summary_frame.setObjectName("summaryFrame")
        sf_layout = QHBoxLayout(self.summary_frame)
        self.summary_label = QLabel("Standing by.")
        self.summary_label.setObjectName("summaryLabel")
        sf_layout.addWidget(self.summary_label, stretch=1)
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setRange(0, 0)
        sf_layout.addWidget(self.progress_bar)
        root_layout.addWidget(self.summary_frame)

    @staticmethod
    def _make_button(text: str, accent: str, slot) -> AnimatedButton:
        btn = AnimatedButton(text, accent)
        btn.setMinimumHeight(48)
        btn.clicked.connect(slot)
        btn.setProperty("accent", accent)
        return btn

    def _set_buttons_enabled(self, enabled: bool):
        for btn in (self.btn_update, self.btn_quick, self.btn_file, self.btn_folder, self.btn_home):
            btn.setEnabled(enabled)
        self.btn_stop.setEnabled(not enabled)

    def _refresh_status(self):
        self._clamscan_path = find_binary("clamscan")
        self._freshclam_path = find_binary("freshclam")
        db_exists = check_virus_db_exists()
        if self._clamscan_path:
            ver = get_clamav_version(self._clamscan_path)
            if not db_exists:
                self.status_label.setText("Intelligence Missing")
                self.status_dot.set_color("#ff9500")
            else:
                self.status_label.setText("Protection Active")
                self.status_dot.set_color("#34c759")
                self.version_label.setText(ver)
            self._set_buttons_enabled(True)
        else:
            self.status_label.setText("ClamAV Not Found")
            self.status_dot.set_color("#ff3b30")
            self._set_buttons_enabled(False)

    def _log(self, text: str):
        self.console.appendPlainText(text)
        self._log_buffer.append(text)

    def _start_command(self, command: list[str], label: str):
        if self._scan_running: return
        self._scan_running = True
        self._log_buffer.clear()
        self.console.clear()
        self._set_buttons_enabled(False)
        self.progress_bar.setVisible(True)
        self.status_dot.start_pulse()
        self._worker = ScanWorker(command, self)
        self._worker.output_line.connect(self._log)
        self._worker.finished_sig.connect(self._on_finished)
        self._worker.start()

    def _on_finished(self, code, elapsed):
        self._scan_running = False
        self._set_buttons_enabled(True)
        self.progress_bar.setVisible(False)
        self.status_dot.stop_pulse()
        self.summary_label.setText(f"Scan complete. Code: {code}")

    def _on_update_definitions(self):
        if self._freshclam_path: self._start_command([self._freshclam_path], "Update")

    def _on_quick_scan(self):
        targets = [str(d) for d in QUICK_SCAN_DIRS if d.exists()]
        if targets: self._start_command([self._clamscan_path, "-r", "--infected"] + targets, "Quick Scan")

    def _on_scan_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if path: self._start_command([self._clamscan_path, "--infected", path], "File Scan")

    def _on_scan_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Select Directory")
        if path: self._start_command([self._clamscan_path, "-r", "--infected", path], "Folder Scan")

    def _on_full_home_scan(self):
        self._start_command([self._clamscan_path, "-r", "--infected", str(HOME_DIR)], "Deep Scan")

    def _on_stop_scan(self):
        if self._worker: self._worker.request_stop()

    def _on_open_logs(self):
        subprocess.Popen(["xdg-open", str(LOGS_DIR)])

    def _on_quarantine(self):
        QMessageBox.information(self, "Quarantine", "Moving to isolation...")

    def _apply_styles(self):
        self.setStyleSheet("""
        QMainWindow, QWidget { background-color: #0c0c0e; color: #f5f5f7; font-family: "Ubuntu", sans-serif; }
        #appTitle { font-size: 24px; font-weight: bold; }
        #statusCard { background-color: #1c1c1e; border-radius: 12px; border: 1px solid #38383a; }
        QPushButton { background-color: #2c2c2e; border-radius: 8px; padding: 10px; }
        #console { background-color: #000000; color: #30d158; font-family: "Ubuntu Mono", monospace; }
        """)

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
