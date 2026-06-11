# 🦪 Open Clam Scanner

A beginner-friendly, cross-platform antivirus scanner GUI powered by [ClamAV](https://www.clamav.net/).

![Python](https://img.shields.io/badge/Python-3.9+-blue)
![PyQt6](https://img.shields.io/badge/GUI-PyQt6-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

## Features

- **Auto-detect** ClamAV installation and show version info
- **Update virus definitions** via `freshclam`
- **Multiple scan modes**: Quick Scan, File Scan, Folder Scan, Full Home Scan
- **Live terminal output** inside the app
- **Scan summary** with file counts, infections, errors, and elapsed time
- **Result indicators**: Clean ✅ · Threats Found ⚠️ · Scan Failed ❌
- **Scan logs** saved automatically with a "Reveal in Finder" button
- **Stop scan** button for long-running scans
- **Optional quarantine** — moves files only after user confirmation
- **Safe by design** — never deletes files automatically

## Prerequisites

### macOS (Homebrew)

```bash
brew install clamav
```

After installing, create the freshclam config:

```bash
cp /opt/homebrew/etc/clamav/freshclam.conf.sample /opt/homebrew/etc/clamav/freshclam.conf
# Edit freshclam.conf and comment out or remove the line "Example"
sed -i '' 's/^Example/#Example/' /opt/homebrew/etc/clamav/freshclam.conf
```

### Linux (Debian/Ubuntu)

```bash
sudo apt install clamav clamav-daemon
sudo freshclam
```

### Windows

Download the ClamAV installer from [clamav.net/downloads](https://www.clamav.net/downloads) and ensure `clamscan.exe` and `freshclam.exe` are on your `PATH`.

## Installation

```bash
# Clone or download this repository
cd clam

# Create a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate   # macOS/Linux
# venv\Scripts\activate    # Windows

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
python open_clam_scanner.py
```

## Project Structure

```
clam/
├── open_clam_scanner.py   # Main application (single file, fully self-contained)
├── requirements.txt       # Python dependencies
├── README.md              # This file
└── logs/                  # Created automatically — scan logs go here
```

## Safety Notes

- This app **never deletes files** automatically.
- If threats are found, it shows file paths and recommends manual review.
- Quarantine moves files only after explicit user confirmation.
- No admin/root permissions are required for basic scans.

## License

MIT
