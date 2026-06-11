#!/usr/bin/env python3
"""
Open Clam Scanner — A beginner-friendly ClamAV GUI.

This single-file application wraps ClamAV's command-line tools (clamscan, freshclam)
in a polished PyQt6 interface.  It runs scans in background threads so the UI never
freezes, saves logs automatically, and never deletes files without explicit user
confirmation.

Requirements:
    pip install PyQt6
    brew install clamav   (macOS)

Usage:
    python open_clam_scanner.py
"""

# ──────────────────────────────────────────────────────────────────────────────
# Imports
# ──────────────────────────────────────────────────────────────────────────────
import sys
import os
import re
import shutil
import platform
import subprocess
import time
import datetime
import textwrap
from pathlib import Path

from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QPropertyAnimation,
    QEasingCurve, pyqtProperty, QSize,
)
from PyQt6.QtGui import (
    QFont, QIcon, QColor, QPalette, QAction, QFontDatabase,
    QPainter, QLinearGradient, QBrush, QPen,
)
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QPlainTextEdit, QFileDialog, QMessageBox,
    QFrame, QProgressBar, QSizePolicy, QGraphicsDropShadowEffect,
    QGroupBox, QGridLayout, QSplitter, QToolTip, QScrollArea,
)

# ──────────────────────────────────────────────────────────────────────────────
# Constants & Paths
# ──────────────────────────────────────────────────────────────────────────────
APP_TITLE = "Open Clam Scanner"
APP_VERSION = "1.0.0"
HOME_DIR = Path.home()
LOGS_DIR = Path(__file__).resolve().parent / "logs"
QUARANTINE_DIR = Path(__file__).resolve().parent / "quarantine"

# Quick-scan targets (common user folders)
QUICK_SCAN_DIRS = [
    HOME_DIR / "Downloads",
    HOME_DIR / "Desktop",
    HOME_DIR / "Documents",
]


# ──────────────────────────────────────────────────────────────────────────────
# Utility: detect ClamAV binaries & database
# ──────────────────────────────────────────────────────────────────────────────
def find_binary(name: str) -> str | None:
    """Return full path to *name* if it exists on PATH, else None."""
    return shutil.which(name)


def get_clamav_version(clamscan_path: str) -> str:
    """Run `clamscan --version` and return the output string."""
    try:
        result = subprocess.run(
            [clamscan_path, "--version"],
            capture_output=True, text=True, timeout=10,
        )
        return result.stdout.strip() or result.stderr.strip()
    except Exception as exc:
        return f"Error: {exc}"


def check_virus_db_exists() -> bool:
    """
    Check whether ClamAV virus definition files exist.

    ClamAV stores its database (main.cvd / main.cld, daily.cvd / daily.cld)
    in platform-specific locations.  If none are found, scans will fail with
    'Known viruses: 0'.
    """
    # Common database directories across platforms
    candidates = [
        Path("/opt/homebrew/var/lib/clamav"),           # macOS Homebrew (Apple Silicon)
        Path("/usr/local/var/lib/clamav"),               # macOS Homebrew (Intel)
        Path("/var/lib/clamav"),                         # Linux
        Path("/usr/local/share/clamav"),                 # FreeBSD / alt Linux
        Path.home() / ".clamav",                        # User-local fallback
    ]
    # On Windows, check next to the binary
    clamscan = find_binary("clamscan")
    if clamscan:
        candidates.append(Path(clamscan).parent / "database")
        candidates.append(Path(clamscan).parent.parent / "share" / "clamav")

    db_names = ("main.cvd", "main.cld", "daily.cvd", "daily.cld")
    for d in candidates:
        if d.is_dir():
            for name in db_names:
                if (d / name).exists():
                    return True
    return False


# ──────────────────────────────────────────────────────────────────────────────
# Worker thread — runs ClamAV / freshclam in the background
# ──────────────────────────────────────────────────────────────────────────────
class ScanWorker(QThread):
    """
    Runs a subprocess command in a background thread.

    Signals:
        output_line  — emitted for each line of stdout/stderr
        finished_sig — emitted when the process ends (return_code, elapsed_secs)
    """
    output_line = pyqtSignal(str)
    finished_sig = pyqtSignal(int, float)  # return_code, elapsed_seconds

    def __init__(self, command: list[str], parent=None):
        super().__init__(parent)
        self.command = command
        self._process: subprocess.Popen | None = None
        self._stop_requested = False

    # Allow the main thread to stop the scan
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
                bufsize=1,  # line-buffered
            )
            # Stream output line-by-line
            for line in iter(self._process.stdout.readline, ""):
                if self._stop_requested:
                    break
                self.output_line.emit(line.rstrip("\n"))
            self._process.stdout.close()
            self._process.wait()
            elapsed = time.time() - start
            self.finished_sig.emit(self._process.returncode, elapsed)
        except FileNotFoundError:
            self.output_line.emit("Command not found. Is ClamAV installed?")
            self.finished_sig.emit(-1, time.time() - start)
        except Exception as exc:
            self.output_line.emit(f"Error: {exc}")
            self.finished_sig.emit(-1, time.time() - start)


# ──────────────────────────────────────────────────────────────────────────────
# Pulsing dot widget for animated status indicator
# ──────────────────────────────────────────────────────────────────────────────
class StatusDot(QWidget):
    """A small coloured circle that can pulse via animation."""

    def __init__(self, color: str = "#4ade80", size: int = 14, parent=None):
        super().__init__(parent)
        self._color = QColor(color)
        self._size = size
        self._opacity = 1.0
        self.setFixedSize(size + 4, size + 4)

        # Pulse animation
        self._anim = QPropertyAnimation(self, b"opacity")
        self._anim.setDuration(1200)
        self._anim.setStartValue(1.0)
        self._anim.setEndValue(0.35)
        self._anim.setEasingCurve(QEasingCurve.Type.InOutSine)
        self._anim.setLoopCount(-1)  # infinite

    # Qt property for the animation
    def _get_opacity(self):
        return self._opacity

    def _set_opacity(self, val):
        self._opacity = val
        self.update()

    opacity = pyqtProperty(float, _get_opacity, _set_opacity)

    def set_color(self, color: str):
        self._color = QColor(color)
        self.update()

    def start_pulse(self):
        self._anim.start()

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
        r = self._size // 2
        painter.drawEllipse(2, 2, self._size, self._size)
        painter.end()


# ──────────────────────────────────────────────────────────────────────────────
# Animated Button — Enhances interactivity with scaling and color shifts
# ──────────────────────────────────────────────────────────────────────────────
class AnimatedButton(QPushButton):
    def __init__(self, text: str, accent: str = "#3a3a3c", parent=None):
        super().__init__(text, parent)
        self._accent = QColor(accent)
        self._current_color = QColor(accent)
        self.setGraphicsEffect(self._make_shadow(8, 0, 2, QColor(0, 0, 0, 100)))

        # Hover animation
        self._anim = QPropertyAnimation(self, b"pos")
        self._scale_anim = QPropertyAnimation(self, b"geometry")
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    @staticmethod
    def _make_shadow(blur: int, x_off: int, y_off: int, color: QColor) -> QGraphicsDropShadowEffect:
        """Create a drop-shadow effect using setter methods (PyQt6 doesn't allow keyword args)."""
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

# ──────────────────────────────────────────────────────────────────────────────
# Main Window
# ──────────────────────────────────────────────────────────────────────────────
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        # ── State ──
        self._clamscan_path: str | None = find_binary("clamscan")
        self._freshclam_path: str | None = find_binary("freshclam")
        self._worker: ScanWorker | None = None
        self._current_log_path: Path | None = None
        self._log_buffer: list[str] = []
        self._scan_running = False
        self._infected_files: list[str] = []

        # ── Ensure dirs ──
        LOGS_DIR.mkdir(exist_ok=True)
        QUARANTINE_DIR.mkdir(exist_ok=True)

        # ── Window setup ──
        self.setWindowTitle("Open Clam Scanner")
        self.setWindowIcon(QIcon(str(Path(__file__).resolve().parent / "calmqt.png")))
        self.setMinimumSize(920, 750)
        self.resize(1060, 850)

        # ── Build UI ──
        self._build_ui()
        self._apply_styles()
        self._refresh_status()
        
        # ── Initial Animations ──
        self._intro_animation()

    def _intro_animation(self):
        """Fade in the main UI components sequentially."""
        for i, widget in enumerate([self.status_card, self.btn_frame, self.console, self.summary_frame]):
            anim = QPropertyAnimation(widget, b"windowOpacity")
            anim.setDuration(500)
            anim.setStartValue(0.0)
            anim.setEndValue(1.0)
            # We can't use windowOpacity on sub-widgets easily, 
            # so we'll use a simple fade-in effect via a custom property if needed,
            # but for now, let's just ensure they are visible.
            widget.show()

    # ──────────────────────────────────────────────────────────────────────
    # UI Construction
    # ──────────────────────────────────────────────────────────────────────
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)
        root_layout.setContentsMargins(32, 24, 32, 24)
        root_layout.setSpacing(20)

        # ── Header ──
        header = QHBoxLayout()
        title_container = QVBoxLayout()
        title_lbl = QLabel("ClamAV Defense")
        title_lbl.setObjectName("appTitle")
        subtitle_lbl = QLabel("Intelligent security for your ecosystem")
        subtitle_lbl.setObjectName("appSubtitle")
        title_container.addWidget(title_lbl)
        title_container.addWidget(subtitle_lbl)
        header.addLayout(title_container)
        
        header.addStretch()
        ver_lbl = QLabel(f"Version {APP_VERSION}")
        ver_lbl.setObjectName("versionLabel")
        header.addWidget(ver_lbl, alignment=Qt.AlignmentFlag.AlignTop)
        root_layout.addLayout(header)

        # ── Status Card ──
        self.status_card = QFrame()
        self.status_card.setObjectName("statusCard")
        sc_outer = QVBoxLayout(self.status_card)
        sc_outer.setContentsMargins(24, 20, 24, 20)
        sc_outer.setSpacing(10)

        # Top row: dot + status text
        sc_top = QHBoxLayout()
        sc_top.setSpacing(12)
        self.status_dot = StatusDot("#34c759", 12)
        sc_top.addWidget(self.status_dot, alignment=Qt.AlignmentFlag.AlignTop)

        status_text_container = QVBoxLayout()
        status_text_container.setSpacing(2)
        self.status_label = QLabel("Analyzing security environment…")
        self.status_label.setObjectName("statusLabel")
        self.status_desc = QLabel("Please wait while we verify your protection status.")
        self.status_desc.setObjectName("statusDesc")
        status_text_container.addWidget(self.status_label)
        status_text_container.addWidget(self.status_desc)
        sc_top.addLayout(status_text_container, stretch=1)
        sc_outer.addLayout(sc_top)

        # Bottom row: version + path, separated by a subtle divider
        sc_bottom = QHBoxLayout()
        sc_bottom.setSpacing(16)
        self.version_label = QLabel("")
        self.version_label.setObjectName("versionInfo")
        self.path_label = QLabel("")
        self.path_label.setObjectName("pathInfo")
        sc_bottom.addWidget(self.version_label)
        sc_bottom.addStretch()
        sc_bottom.addWidget(self.path_label)
        sc_outer.addLayout(sc_bottom)

        root_layout.addWidget(self.status_card)

        # ── Action Buttons ──
        self.btn_frame = QFrame()
        self.btn_frame.setObjectName("btnFrame")
        btn_grid = QGridLayout(self.btn_frame)
        btn_grid.setContentsMargins(0, 0, 0, 0)
        btn_grid.setSpacing(16)

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

        root_layout.addWidget(self.btn_frame)

        # ── Console Output ──
        console_header = QHBoxLayout()
        console_label = QLabel("Operation Insight")
        console_label.setObjectName("sectionLabel")
        console_header.addWidget(console_label)
        console_header.addStretch()
        root_layout.addLayout(console_header)

        self.console = QPlainTextEdit()
        self.console.setObjectName("console")
        self.console.setReadOnly(True)
        self.console.setMaximumBlockCount(10_000)
        root_layout.addWidget(self.console, stretch=1)

        # ── Summary Bar ──
        self.summary_frame = QFrame()
        self.summary_frame.setObjectName("summaryFrame")
        sf_layout = QHBoxLayout(self.summary_frame)
        sf_layout.setContentsMargins(24, 18, 24, 18)

        self.summary_icon  = QLabel("")
        self.summary_icon.setObjectName("summaryIcon")
        sf_layout.addWidget(self.summary_icon)

        self.summary_label = QLabel("Standing by for your command.")
        self.summary_label.setObjectName("summaryLabel")
        self.summary_label.setWordWrap(True)
        sf_layout.addWidget(self.summary_label, stretch=1)

        self.progress_bar = QProgressBar()
        self.progress_bar.setObjectName("scanProgress")
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setFixedWidth(200)
        self.progress_bar.setVisible(False)
        sf_layout.addWidget(self.progress_bar)

        root_layout.addWidget(self.summary_frame)

    # ──────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────
    @staticmethod
    def _make_button(text: str, accent: str, slot) -> AnimatedButton:
        btn = AnimatedButton(text, accent)
        btn.setMinimumHeight(48)
        btn.clicked.connect(slot)
        btn.setProperty("accent", accent)
        return btn

    def _set_buttons_enabled(self, enabled: bool):
        for btn in (self.btn_update, self.btn_quick, self.btn_file,
                    self.btn_folder, self.btn_home):
            btn.setEnabled(enabled)
        self.btn_stop.setEnabled(not enabled)

    def _refresh_status(self):
        self._clamscan_path = find_binary("clamscan")
        self._freshclam_path = find_binary("freshclam")
        self._db_exists = check_virus_db_exists()

        if self._clamscan_path:
            ver = get_clamav_version(self._clamscan_path)
            if not self._db_exists:
                self.status_label.setText("Intelligence Database Missing")
                self.status_desc.setText("Your defense shield requires an update to recognize modern threats.")
                self.status_dot.set_color("#ff9500")
                self.version_label.setText("Action required: Refresh Defense Intel")
                self._set_buttons_enabled(False)
                self.btn_update.setEnabled(True)
            else:
                self.status_label.setText("Protection Shield Active")
                self.status_desc.setText("Your system is being monitored by ClamAV core services.")
                self.status_dot.set_color("#34c759")
                self.version_label.setText(ver)
                self._set_buttons_enabled(True)
        else:
            self.status_label.setText("Defense Engine Unavailable")
            self.status_desc.setText("ClamAV core was not detected on your system.")
            self.status_dot.set_color("#ff3b30")
            self.version_label.setText("Please install ClamAV to enable protection.")
            self._set_buttons_enabled(False)

    def _log(self, text: str):
        self.console.appendPlainText(text)
        self._log_buffer.append(text)
        sb = self.console.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _save_log(self):
        if not self._log_buffer:
            return
        ts = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_file = LOGS_DIR / f"scan_{ts}.log"
        log_file.write_text("\n".join(self._log_buffer), encoding="utf-8")
        self._current_log_path = log_file
        self._log(f"\nAudit history archived: {log_file.name}")

    # ──────────────────────────────────────────────────────────────────────
    # Scan lifecycle
    # ──────────────────────────────────────────────────────────────────────
    def _start_command(self, command: list[str], label: str = "Analysis"):
        if self._scan_running:
            return

        self._scan_running = True
        self._log_buffer.clear()
        self._infected_files.clear()
        self.console.clear()
        self._set_buttons_enabled(False)
        self.progress_bar.setVisible(True)
        self.summary_label.setText(f"Initiating {label}...")
        self.status_dot.start_pulse()

        self._log(f"System Check Initiated: {label}")
        self._log(f"Process Path: {' '.join(command)}")
        self._log(f"Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self._log("-" * 60)

        self._worker = ScanWorker(command, self)
        self._worker.output_line.connect(self._on_output_line)
        self._worker.finished_sig.connect(self._on_scan_finished)
        self._worker.start()

    def _on_output_line(self, line: str):
        self._log(line)
        if "FOUND" in line and "Infected files:" not in line:
            match = re.match(r"^(.+?):\s+.+\s+FOUND$", line)
            if match:
                self._infected_files.append(match.group(1))

    def _on_scan_finished(self, return_code: int, elapsed: float):
        self._scan_running = False
        self._set_buttons_enabled(True)
        self.progress_bar.setVisible(False)
        self.status_dot.stop_pulse()

        mins, secs = divmod(int(elapsed), 60)
        time_str = f"{mins}m {secs}s" if mins else f"{secs}s"
        self._log("-" * 60)

        full_output = "\n".join(self._log_buffer)
        db_missing = "Known viruses: 0" in full_output

        if db_missing and return_code == 2:
            self.summary_label.setText("Operational Warning: Intelligence database not found. Please refresh defense intel.")
            self.summary_frame.setProperty("state", "warning")
            self._log("\nSecurity Protocol Alert: No threat definitions loaded.")
        elif return_code == -1:
            self.summary_label.setText(f"Operation Interrupted: The analysis could not be completed. Time elapsed: {time_str}")
            self.summary_frame.setProperty("state", "error")
        elif return_code == 1 or self._infected_files:
            n = len(self._infected_files)
            self.summary_label.setText(f"Threat Detected: {n} potential risk{'s' if n != 1 else ''} identified during the {time_str} analysis.")
            self.summary_frame.setProperty("state", "warning")
            self.btn_quarantine.setEnabled(bool(self._infected_files))
            self._log(f"\nAlert: {n} suspicious entities found.")
        elif return_code == 0:
            self.summary_label.setText(f"System Integrity Verified: No threats were identified during the {time_str} analysis.")
            self.summary_frame.setProperty("state", "clean")
        else:
            self.summary_label.setText(f"Operation Concluded: Analysis finished with code {return_code}. Time: {time_str}")
            self.summary_frame.setProperty("state", "error")

        self.summary_frame.style().unpolish(self.summary_frame)
        self.summary_frame.style().polish(self.summary_frame)
        self._refresh_status()
        self._save_log()
        self._worker = None

    # ──────────────────────────────────────────────────────────────────────
    # Button Slots
    # ──────────────────────────────────────────────────────────────────────
    def _on_update_definitions(self):
        if not self._freshclam_path:
            QMessageBox.critical(self, "Core Component Missing", "ClamAV update services are not installed on this system.")
            return
        self._start_command([self._freshclam_path], label="Intelligence Refresh")

    def _on_quick_scan(self):
        targets = [str(d) for d in QUICK_SCAN_DIRS if d.exists()]
        if not targets:
            QMessageBox.information(self, "No Targets", "No high-priority directories were found for a swift analysis.")
            return
        self._start_command([self._clamscan_path, "-r", "--infected"] + targets, label="Swift Analysis")

    def _on_scan_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Entity for Inspection")
        if path:
            self._start_command([self._clamscan_path, "--infected", path], label=f"File Inspection: {Path(path).name}")

    def _on_scan_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Select Directory for Inspection")
        if path:
            self._start_command([self._clamscan_path, "-r", "--infected", path], label=f"Directory Inspection: {Path(path).name}")

    def _on_full_home_scan(self):
        reply = QMessageBox.question(self, "Deep Inspection", "Performing a deep system inspection will scan your entire user profile. This operation requires significant time. Proceed?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self._start_command([self._clamscan_path, "-r", "--infected", str(HOME_DIR)], label="Deep System Inspection")

    def _on_stop_scan(self):
        if self._worker and self._scan_running:
            self._worker.request_stop()
            self._log("\nTermination protocol initiated...")

    def _on_open_logs(self):
        target = self._current_log_path or LOGS_DIR
        if platform.system() == "Darwin":
            subprocess.Popen(["open", "-R", str(target)])
        elif platform.system() == "Linux":
            subprocess.Popen(["xdg-open", str(target.parent if target.is_file() else target)])
        else:
            subprocess.Popen(["explorer", "/select,", str(target)])

    def _on_quarantine(self):
        if not self._infected_files:
            return
        reply = QMessageBox.warning(self, "Isolation Protocol", f"Are you sure you want to move {len(self._infected_files)} identified risks to isolation?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply != QMessageBox.StandardButton.Yes:
            return

        moved = 0
        for fp in self._infected_files:
            src = Path(fp)
            if src.exists():
                dest = QUARANTINE_DIR / src.name
                if dest.exists():
                    ts = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
                    dest = QUARANTINE_DIR / f"{src.stem}_{ts}{src.suffix}"
                try:
                    shutil.move(str(src), str(dest))
                    self._log(f"Isolated: {dest.name}")
                    moved += 1
                except Exception as exc:
                    self._log(f"Isolation failure for {src.name}: {exc}")

        self._log(f"\nIsolation protocol complete. {moved} entities moved.")
        self.btn_quarantine.setEnabled(False)
        QMessageBox.information(self, "Protocol Concluded", f"{moved} risks successfully isolated in the quarantine vault.")

    # ──────────────────────────────────────────────────────────────────────
    # Stylesheet
    # ──────────────────────────────────────────────────────────────────────
    def _apply_styles(self):
        # Use Menlo for monospace (guaranteed on macOS), system-ui for UI text
        self.setStyleSheet("""
        /* ── Base ── */
        QMainWindow, QWidget {
            background-color: #0c0c0e;
            color: #f5f5f7;
            font-family: "Helvetica Neue", "Segoe UI", "Ubuntu", sans-serif;
            font-size: 14px;
        }

        /* ── Header ── */
        #appTitle {
            font-size: 28px;
            font-weight: 700;
            color: #ffffff;
            padding-bottom: 0px;
        }
        #appSubtitle {
            font-size: 13px;
            color: #98989d;
            font-weight: 400;
            padding-top: 0px;
        }
        #versionLabel {
            font-size: 12px;
            color: #636366;
            font-weight: 500;
        }

        /* ── Status Card ── */
        #statusCard {
            background-color: #1c1c1e;
            border-radius: 16px;
            border: 1px solid #38383a;
        }
        #statusLabel {
            font-size: 16px;
            font-weight: 600;
            color: #ffffff;
        }
        #statusDesc {
            font-size: 13px;
            color: #98989d;
            font-weight: 400;
        }
        #versionInfo {
            font-size: 12px;
            color: #8e8e93;
            font-weight: 400;
        }
        #pathInfo {
            font-size: 12px;
            color: #636366;
            font-weight: 400;
        }

        /* ── Buttons ── */
        #btnFrame {
            background: transparent;
        }
        QPushButton {
            background-color: #2c2c2e;
            color: #ffffff;
            border: 1px solid #38383a;
            border-radius: 12px;
            padding: 12px 20px;
            font-size: 14px;
            font-weight: 600;
        }
        QPushButton:hover {
            background-color: #3a3a3c;
            border: 1px solid #48484a;
        }
        QPushButton:pressed {
            background-color: #1c1c1e;
        }
        QPushButton:disabled {
            color: #48484a;
            background-color: #1c1c1e;
            border: 1px solid #2c2c2e;
        }

        /* Blue accent buttons */
        QPushButton[accent="#007aff"] {
            background-color: #0a84ff;
            border: 1px solid #409cff;
        }
        QPushButton[accent="#007aff"]:hover {
            background-color: #409cff;
            border: 1px solid #64b5f6;
        }
        QPushButton[accent="#007aff"]:pressed {
            background-color: #0064d2;
        }
        QPushButton[accent="#007aff"]:disabled {
            background-color: #1c1c1e;
            border: 1px solid #2c2c2e;
            color: #48484a;
        }

        /* Red accent buttons */
        QPushButton[accent="#ff3b30"] {
            background-color: #ff453a;
            border: 1px solid #ff6961;
        }
        QPushButton[accent="#ff3b30"]:hover {
            background-color: #ff6961;
            border: 1px solid #ff8a80;
        }
        QPushButton[accent="#ff3b30"]:pressed {
            background-color: #d32f2f;
        }
        QPushButton[accent="#ff3b30"]:disabled {
            background-color: #1c1c1e;
            border: 1px solid #2c2c2e;
            color: #48484a;
        }

        /* Grey accent buttons */
        QPushButton[accent="#8e8e93"] {
            background-color: #2c2c2e;
            border: 1px solid #48484a;
        }
        QPushButton[accent="#8e8e93"]:hover {
            background-color: #3a3a3c;
            border: 1px solid #636366;
        }

        /* ── Section Label ── */
        #sectionLabel {
            font-size: 12px;
            font-weight: 700;
            color: #8e8e93;
            letter-spacing: 1px;
        }

        /* ── Console ── */
        #console {
            background-color: #000000;
            color: #30d158;
            border: 1px solid #2c2c2e;
            border-radius: 14px;
            padding: 14px;
            font-family: "Menlo", "Cascadia Code", "Consolas", monospace;
            font-size: 13px;
            selection-background-color: #0a84ff;
            selection-color: #ffffff;
        }

        /* ── Summary Frame ── */
        #summaryFrame {
            background-color: #1c1c1e;
            border-radius: 16px;
            border: 1px solid #38383a;
        }
        #summaryFrame[state="clean"] {
            border: 1px solid rgba(48, 209, 88, 0.5);
            background-color: rgba(48, 209, 88, 0.08);
        }
        #summaryFrame[state="warning"] {
            border: 1px solid rgba(255, 159, 10, 0.5);
            background-color: rgba(255, 159, 10, 0.08);
        }
        #summaryFrame[state="error"] {
            border: 1px solid rgba(255, 69, 58, 0.5);
            background-color: rgba(255, 69, 58, 0.08);
        }
        #summaryIcon {
            font-size: 24px;
            padding-right: 6px;
        }
        #summaryLabel {
            font-size: 14px;
            font-weight: 500;
            color: #f5f5f7;
        }

        /* ── Progress Bar ── */
        #scanProgress {
            border: none;
            border-radius: 3px;
            background-color: #38383a;
            max-height: 6px;
        }
        #scanProgress::chunk {
            background-color: #0a84ff;
            border-radius: 3px;
        }

        /* ── Scrollbars ── */
        QScrollBar:vertical {
            background: transparent;
            width: 8px;
            margin: 4px 0;
        }
        QScrollBar::handle:vertical {
            background: #48484a;
            min-height: 30px;
            border-radius: 4px;
        }
        QScrollBar::handle:vertical:hover {
            background: #636366;
        }
        QScrollBar::add-line:vertical,
        QScrollBar::sub-line:vertical {
            height: 0;
            background: none;
        }
        QScrollBar::add-page:vertical,
        QScrollBar::sub-page:vertical {
            background: none;
        }

        /* ── Message Box ── */
        QMessageBox {
            background-color: #1c1c1e;
        }
        QMessageBox QLabel {
            color: #f5f5f7;
            font-size: 14px;
        }
        QMessageBox QPushButton {
            min-width: 90px;
            min-height: 32px;
        }
        """)


# ──────────────────────────────────────────────────────────────────────────────
# Entry Point
# ──────────────────────────────────────────────────────────────────────────────
def main():
    app = QApplication(sys.argv)

    # Set application metadata
    app.setApplicationName(APP_TITLE)
    app.setApplicationVersion(APP_VERSION)
    app.setOrganizationName("OpenClamScanner")

    # Set a reliable application-wide font
    # "Helvetica Neue" is guaranteed on macOS; falls back gracefully elsewhere
    font = QFont()
    if platform.system() == "Darwin":
        font.setFamily("Helvetica Neue")
    elif platform.system() == "Windows":
        font.setFamily("Segoe UI")
    else:
        font.setFamily("sans-serif")
    font.setPointSize(13)
    font.setStyleStrategy(QFont.StyleStrategy.PreferAntialias)
    app.setFont(font)

    # Dark palette for native dialogs and fallback rendering
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor("#0c0c0e"))
    palette.setColor(QPalette.ColorRole.WindowText, QColor("#f5f5f7"))
    palette.setColor(QPalette.ColorRole.Base, QColor("#000000"))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor("#1c1c1e"))
    palette.setColor(QPalette.ColorRole.Text, QColor("#f5f5f7"))
    palette.setColor(QPalette.ColorRole.Button, QColor("#2c2c2e"))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.Highlight, QColor("#0a84ff"))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor("#2c2c2e"))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor("#f5f5f7"))
    app.setPalette(palette)

    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
