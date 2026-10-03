# 🛡 AV Folder Monitor

**Automatically virus-scan new files the moment they land in your folders.** Watch up to three folders (Downloads, a shared drive, a torrent folder…). Whenever something new appears, the monitor batches the changes and runs your antivirus' command-line scanner on just those files. It keeps a history of every scan and every threat found.

![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-0078D6)
![Python](https://img.shields.io/badge/python-3.9%2B-3776AB)
![License](https://img.shields.io/badge/license-MIT-green)

## Features

- 👀 **Watches up to 3 folders recursively** for new and changed files and folders, using [watchdog](https://github.com/gorakhargosh/watchdog).
- 🛡 **Uses the antivirus you already have**, auto-detected in this order:
  1. **Windows Defender**: `MpCmdRun.exe`, built into every Windows 10/11
  2. **AVG Business**: `ashCmd.exe`
  3. **AVG Legacy**: `avgscanx.exe` (pre-2019 installs)

  You can also point it at a scanner manually.
- 🧠 **Smart queue**:
  - **Debounce**: waits a few seconds after the last change before scanning, so a big download is scanned once and not mid-write.
  - **Path optimisation**: many files in one folder become a single folder scan.
  - **Deduplication**: child paths are dropped when their parent is already queued.
  - **No overlap**: events that arrive during a scan are queued for the next one.
- 📋 **Live log**, 🕐 **scan history** and 🚨 **threats** tabs, stored in a local SQLite database.
- 🔍 **Manual scan** button, plus archive scanning and heuristics options (AVG).

## Requirements

- **Windows 10/11**
- **Python 3.9+** (tkinter is included with the python.org installer)
- Windows Defender (built in) or AVG

## Installation & usage

```bash
git clone https://github.com/deniskostadinov1995/av-folder-monitor.git
cd av-folder-monitor
pip install -r requirements.txt
python avg_monitor.py
```

Or double-click **`AV Folder Monitor.bat`** to start it without a console window. If `watchdog` isn't installed, the app installs it on first start.

1. Pick up to **three folders** to watch.
2. Check the detected **scanner path** (Defender is found automatically).
3. Set the **scan delay** (debounce, in seconds) and press **💾 Save Settings**.
4. Press **▶ Start Monitoring**.

Settings are saved to `avg_monitor_config.json` and the scan history to `avg_monitor_history.db`, both next to the script.

> To start it with Windows, put a shortcut to `AV Folder Monitor.bat` in your Startup folder (`Win + R` → `shell:startup`).

## License

[MIT](LICENSE) © Denis Kostadinov
