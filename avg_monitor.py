#!/usr/bin/env python3
"""
AV Folder Monitor v1.1
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Watches up to 3 folders (recursively) for new files/folders,
then auto-triggers an antivirus scan with smart batching.

Scanner engine priority (auto-detected):
  1. Windows Defender  MpCmdRun.exe  ← built into every Win 10/11
  2. AVG Business      ashCmd.exe    ← only in AVG Business editions
  3. AVG Legacy        avgscanx.exe  ← pre-2019 installs

Smart Queue features:
  • Debounce: waits N seconds after last event before scanning
  • Path optimization: groups files from same dir → scan dir once
  • Concurrent protection: queues incoming events during active scan
  • Deduplication: removes child paths when parent is already queued

Requirements: pip install watchdog
"""

import os, sys, time, json, sqlite3, threading, subprocess
from pathlib import Path
from datetime import datetime
from collections import defaultdict

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

# ─────────────────────────────────────────────────────────────
# AUTO-INSTALL watchdog
# ─────────────────────────────────────────────────────────────
def _ensure_watchdog():
    try:
        from watchdog.observers import Observer  # noqa
    except ImportError:
        print("[AVGMonitor] Installing watchdog library...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "watchdog", "--quiet"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
_ensure_watchdog()

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ─────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────
APP_DIR       = Path(__file__).parent
CONFIG_FILE   = APP_DIR / "avg_monitor_config.json"
DB_FILE       = APP_DIR / "avg_monitor_history.db"
REPORT_FILE   = APP_DIR / "avg_temp_report.txt"

# Engine types — used to pick the right CLI flags
ENG_DEFENDER = "defender"   # Windows Defender  MpCmdRun.exe  (built-in, Win 10/11)
ENG_AVG_BIZ  = "avg_biz"    # AVG Business       ashCmd.exe
ENG_AVG_OLD  = "avg_old"    # AVG Legacy         avgscanx.exe (pre-2019)

# Fixed paths checked in order; first hit wins
SCANNER_FIXED_PATHS = [
    # ── Windows Defender (priority 1 — always present on Win 10/11) ──────────
    r"C:\Program Files\Windows Defender\MpCmdRun.exe",
    r"C:\Program Files (x86)\Windows Defender\MpCmdRun.exe",
    # ── AVG Business editions (priority 2 — uncommon on home PCs) ────────────
    r"C:\Program Files\AVG\Antivirus\ashCmd.exe",
    r"C:\Program Files (x86)\AVG\Antivirus\ashCmd.exe",
    r"C:\Program Files\AVG\AVG Internet Security Business Edition\ashCmd.exe",
    r"C:\Program Files\AVG\AVG AntiVirus Business Edition\ashCmd.exe",
    r"C:\Program Files\Avast Software\Avast\ashCmd.exe",
    r"C:\Program Files (x86)\Avast Software\Avast\ashCmd.exe",
    # ── AVG Legacy (priority 3 — pre-2019 installs) ───────────────────────────
    r"C:\Program Files\AVG\Antivirus\avgscanx.exe",
    r"C:\Program Files (x86)\AVG\Antivirus\avgscanx.exe",
]

MULTI_FILE_THRESHOLD = 3   # If ≥ N files from same dir are queued → scan the whole dir
DEFAULT_DEBOUNCE     = 5   # Seconds to wait after last event before firing scan
SCAN_TIMEOUT         = 600 # Max seconds per scan path (10 min)

# ─────────────────────────────────────────────────────────────
# PALETTE  (deep navy / electric blue / crimson)
# ─────────────────────────────────────────────────────────────
C = {
    "bg":       "#0e1117",
    "bg2":      "#161b27",
    "bg3":      "#1e2637",
    "bg4":      "#252d3d",
    "accent":   "#e63950",
    "blue":     "#4a9eff",
    "green":    "#3ddc84",
    "yellow":   "#f5a623",
    "red":      "#ff4d4d",
    "text":     "#dde3ee",
    "dim":      "#8892a4",
    "border":   "#2a3347",
}

LOG_TAGS = {
    "info":    C["blue"],
    "detect":  C["yellow"],
    "scan":    "#a78bfa",
    "path":    C["dim"],
    "ok":      C["green"],
    "threat":  C["red"],
    "warn":    C["yellow"],
    "error":   C["red"],
    "sep":     C["bg3"],
    "ts":      "#3d4f6e",
}


# ─────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────
class Config:
    _defaults = {
        "folders":        ["", "", ""],
        "scanner_path":   "",
        "debounce":       DEFAULT_DEBOUNCE,
        "scan_archives":  True,
        "heuristics":     True,
    }

    def __init__(self):
        self.data = dict(self._defaults)
        self.data["scanner_path"] = self._detect_scanner()
        self._load()

    def _detect_scanner(self) -> str:
        # 1. Check Windows Defender platform folder first (updated MpCmdRun lives here)
        platform_root = Path(r"C:\ProgramData\Microsoft\Windows Defender\Platform")
        if platform_root.exists():
            try:
                # Each sub-folder is a version like "4.18.24010.12-0"; pick the latest
                versions = sorted(platform_root.iterdir(), reverse=True)
                for v in versions:
                    candidate = v / "MpCmdRun.exe"
                    if candidate.exists():
                        return str(candidate)
            except Exception:
                pass

        # 2. Check all fixed paths in priority order
        for p in SCANNER_FIXED_PATHS:
            if Path(p).exists():
                return p

        # 3. Dynamic walk: look for MpCmdRun.exe under Program Files\Windows Defender
        for base in [r"C:\Program Files", r"C:\Program Files (x86)"]:
            wd = Path(base) / "Windows Defender"
            if wd.exists():
                for c in wd.rglob("MpCmdRun.exe"):
                    return str(c)
            # Also try AVG folder for ashCmd.exe
            avg = Path(base) / "AVG"
            if avg.exists():
                for c in avg.rglob("ashCmd.exe"):
                    return str(c)

        return ""

    def _load(self):
        if CONFIG_FILE.exists():
            try:
                saved = json.loads(CONFIG_FILE.read_text())
                # Migrate old key name if present
                if "avg_path" in saved and "scanner_path" not in saved:
                    saved["scanner_path"] = saved.pop("avg_path")
                self.data.update(saved)
            except Exception:
                pass

    def save(self):
        CONFIG_FILE.write_text(json.dumps(self.data, indent=2))

    @staticmethod
    def engine_type(scanner_path: str) -> str:
        """Identify which engine binary this path points to."""
        name = Path(scanner_path).name.lower() if scanner_path else ""
        if "mpcmdrun" in name:
            return ENG_DEFENDER
        if "ashcmd" in name:
            return ENG_AVG_BIZ
        if "avgscanx" in name:
            return ENG_AVG_OLD
        return ENG_DEFENDER  # safe default


# ─────────────────────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────────────────────
class Database:
    def __init__(self):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(DB_FILE), check_same_thread=False)
        self._init_schema()

    def _init_schema(self):
        with self._conn:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS scans (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at    TEXT NOT NULL,
                    trigger_path  TEXT NOT NULL,
                    scan_paths    TEXT NOT NULL,
                    status        TEXT NOT NULL,
                    threats_found INTEGER DEFAULT 0,
                    duration_sec  REAL,
                    raw_log       TEXT
                );
                CREATE TABLE IF NOT EXISTS threats (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id     INTEGER NOT NULL,
                    detected_at TEXT NOT NULL,
                    file_path   TEXT NOT NULL,
                    threat_name TEXT,
                    action      TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                );
            """)

    # ── writes ──────────────────────────────────────────────
    def insert_scan(self, trigger, paths, status, threats, duration, log) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO scans (started_at,trigger_path,scan_paths,status,"
                "threats_found,duration_sec,raw_log) VALUES (?,?,?,?,?,?,?)",
                (datetime.now().isoformat(), trigger, json.dumps(paths),
                 status, threats, round(duration, 2), log)
            )
            self._conn.commit()
            return cur.lastrowid

    def insert_threat(self, scan_id, file_path, name, action):
        with self._lock:
            self._conn.execute(
                "INSERT INTO threats (scan_id,detected_at,file_path,threat_name,action) "
                "VALUES (?,?,?,?,?)",
                (scan_id, datetime.now().isoformat(), file_path, name, action)
            )
            self._conn.commit()

    # ── reads ────────────────────────────────────────────────
    def get_scans(self, limit=300, status_filter=None) -> list:
        with self._lock:
            if status_filter:
                cur = self._conn.execute(
                    "SELECT * FROM scans WHERE status=? ORDER BY id DESC LIMIT ?",
                    (status_filter, limit)
                )
            else:
                cur = self._conn.execute(
                    "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
                )
            return cur.fetchall()

    def get_scan_by_id(self, scan_id) -> tuple:
        with self._lock:
            cur = self._conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,))
            return cur.fetchone()

    def get_threats(self) -> list:
        with self._lock:
            cur = self._conn.execute("SELECT * FROM threats ORDER BY id DESC")
            return cur.fetchall()

    def clear_all(self):
        with self._lock:
            self._conn.executescript("DELETE FROM threats; DELETE FROM scans;")
            self._conn.commit()


# ─────────────────────────────────────────────────────────────
# SMART SCAN QUEUE
# ─────────────────────────────────────────────────────────────
class SmartScanQueue:
    """
    Collects file-system events, applies debounce + path optimisation,
    then calls `on_ready(paths)` with a de-duplicated scan list.

    Concurrency model
    -----------------
    • While idle  → incoming paths go to `_pending`; debounce timer resets.
    • Timer fires → optimise paths, mark scanning=True, call on_ready().
    • While busy  → incoming paths go to `_next_batch`.
    • scan_done() → merge next_batch into pending, restart debounce.
    """

    def __init__(self, on_ready, on_queued_change=None, debounce_sec=DEFAULT_DEBOUNCE):
        self._on_ready         = on_ready
        self._on_queued_change = on_queued_change   # optional UI callback
        self._debounce_sec     = debounce_sec
        self._pending:   set   = set()
        self._next_batch: set  = set()
        self._scanning         = False
        self._lock             = threading.Lock()
        self._timer            = None

    # ── public ───────────────────────────────────────────────
    def add(self, path: str):
        with self._lock:
            if self._scanning:
                self._next_batch.add(path)
            else:
                self._pending.add(path)
                self._reset_timer()
        self._notify_queued()

    def scan_done(self):
        with self._lock:
            self._scanning = False
            if self._next_batch:
                self._pending.update(self._next_batch)
                self._next_batch.clear()
                self._reset_timer()
        self._notify_queued()

    def queued_count(self) -> int:
        with self._lock:
            return len(self._pending) + len(self._next_batch)

    # ── internal ─────────────────────────────────────────────
    def _reset_timer(self):
        if self._timer:
            self._timer.cancel()
        self._timer = threading.Timer(self._debounce_sec, self._fire)
        self._timer.daemon = True
        self._timer.start()

    def _fire(self):
        with self._lock:
            if not self._pending or self._scanning:
                return
            paths = self._optimise(list(self._pending))
            self._pending.clear()
            self._scanning = True
        self._notify_queued()
        self._on_ready(paths)

    def _optimise(self, raw: list) -> list:
        """
        1. Deduplicate.
        2. Remove paths whose ancestor is already in the list.
        3. Replace N≥MULTI_FILE_THRESHOLD sibling files with their parent dir.
        """
        # Step 1 – unique Path objects
        items = list({Path(p) for p in raw})

        # Step 2 – remove children of existing dirs
        dirs_only = [p for p in items if p.is_dir()]
        pruned = []
        for p in items:
            if not any(p != d and self._child_of(p, d) for d in dirs_only):
                pruned.append(p)

        # Step 3 – group files by parent; collapse if threshold reached
        parent_map: dict = defaultdict(list)
        final = []
        for p in pruned:
            if p.is_dir():
                final.append(p)
            else:
                parent_map[p.parent].append(p)

        for parent, files in parent_map.items():
            if len(files) >= MULTI_FILE_THRESHOLD:
                # Use the parent dir (unless it's already covered)
                if not any(self._child_of(parent, Path(str(f))) for f in final):
                    final.append(parent)
            else:
                final.extend(files)

        result = [str(p) for p in final]
        return result if result else raw

    @staticmethod
    def _child_of(child: Path, parent: Path) -> bool:
        try:
            child.relative_to(parent)
            return child != parent
        except ValueError:
            return False

    def _notify_queued(self):
        if self._on_queued_change:
            try:
                self._on_queued_change(self.queued_count())
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────
# FILE-SYSTEM HANDLER  (watchdog)
# ─────────────────────────────────────────────────────────────
class MediaHandler(FileSystemEventHandler):
    """Watches for created/moved-in events and feeds SmartScanQueue."""

    _THROTTLE_SEC = 2.0   # Ignore same path within this window

    def __init__(self, queue: SmartScanQueue, log_fn):
        self._queue = queue
        self._log   = log_fn
        self._seen: dict = {}
        self._seen_lock  = threading.Lock()

    def on_created(self, event):
        self._handle(event.src_path, event.is_directory, "created")

    def on_moved(self, event):
        self._handle(event.dest_path, event.is_directory, "moved-in")

    def _handle(self, path: str, is_dir: bool, reason: str):
        if not self._throttle(path):
            return
        kind  = "folder" if is_dir else "file"
        name  = Path(path).name
        self._log(f"👁  New {kind} detected ({reason}): {name}", "detect")
        self._queue.add(path)

    def _throttle(self, path: str) -> bool:
        now = time.monotonic()
        with self._seen_lock:
            if path in self._seen and now - self._seen[path] < self._THROTTLE_SEC:
                return False
            self._seen[path] = now
            # Periodic cleanup
            if len(self._seen) > 1000:
                cutoff = now - 30
                self._seen = {k: v for k, v in self._seen.items() if v > cutoff}
        return True


# ─────────────────────────────────────────────────────────────
# ANTIVIRUS SCANNER  (Windows Defender · AVG Business · AVG Legacy)
# ─────────────────────────────────────────────────────────────
class AntivirusScanner:
    """
    Unified scanner wrapper.  Auto-detects engine type from the
    executable name and fires the correct CLI flags.

    Windows Defender  (MpCmdRun.exe)  ← default on Win 10/11
      MpCmdRun.exe -Scan -ScanType 3 -File "<path>" -DisableRemediation
      Exit 0 = clean  |  Exit 2 = threat quarantined  |  Exit 13 = threat (no remediation)

    AVG Business  (ashCmd.exe)
      ashCmd.exe "<path>" /a /c /e=100 /t=A /x=P /r=~<report> /s
      Exit 0 = clean  |  Exit 1 = threat found

    AVG Legacy  (avgscanx.exe)
      avgscanx.exe /SCAN=<path> /REPORT=<report> /REPOK /REPALL /HEUR /ARC
      Exit 0 = clean  |  Exit 1 = threat found
    """

    def __init__(self, scanner_path: str, log_fn, db: Database, cfg: Config):
        self._path   = scanner_path
        self._engine = Config.engine_type(scanner_path)
        self._log    = log_fn
        self._db     = db
        self._cfg    = cfg

    def scan(self, paths: list, trigger: str) -> dict:
        """Scan all paths, aggregate results, persist to DB."""
        if not self._path or not Path(self._path).exists():
            self._log("❌  Scanner executable not found — check Settings!", "error")
            return {"status": "error", "threats": 0, "scan_id": None}

        t0          = time.monotonic()
        all_log     = []
        all_threats = []
        eng_label   = {"defender": "Windows Defender", "avg_biz": "AVG Business",
                       "avg_old": "AVG Legacy"}.get(self._engine, "Scanner")

        self._log("─" * 60, "sep")
        self._log(f"🔍  [{eng_label}]  Batch started — {len(paths)} path(s)", "info")
        for p in paths:
            self._log(f"     ↳ {p}", "path")

        for scan_path in paths:
            if not Path(scan_path).exists():
                self._log(f"⚠   Path vanished before scan: {scan_path}", "warn")
                continue
            self._log(f"📂  Scanning: {Path(scan_path).name}", "scan")

            threats, log_chunk = self._run_single(scan_path)
            all_log.append(log_chunk)
            all_threats.extend(threats)

            if threats:
                for t in threats:
                    self._log(f"🚨  THREAT » {t['file']} — {t['name']}", "threat")
            else:
                self._log(f"✅  Clean: {Path(scan_path).name}", "ok")

        duration = time.monotonic() - t0
        status   = "threats_found" if all_threats else "clean"
        full_log = "\n\n".join(all_log)

        scan_id = self._db.insert_scan(trigger, paths, status,
                                       len(all_threats), duration, full_log)
        for t in all_threats:
            self._db.insert_threat(scan_id, t["file"], t["name"],
                                   t.get("action", "detected"))

        emoji = "🚨" if all_threats else "✅"
        self._log(
            f"{emoji}  Batch done in {duration:.1f}s — {len(all_threats)} threat(s) found",
            "threat" if all_threats else "ok"
        )
        self._log("─" * 60, "sep")
        return {"status": status, "threats": len(all_threats), "scan_id": scan_id}

    # ── single-path dispatch ──────────────────────────────────
    def _run_single(self, path: str) -> tuple:
        if self._engine == ENG_DEFENDER:
            return self._run_defender(path)
        elif self._engine == ENG_AVG_BIZ:
            return self._run_avg_biz(path)
        else:
            return self._run_avg_old(path)

    # ── Windows Defender ─────────────────────────────────────
    def _run_defender(self, path: str) -> tuple:
        """
        MpCmdRun.exe -Scan -ScanType 3 -File "<path>" -DisableRemediation
          -ScanType 3  = custom path scan
          -DisableRemediation  = detect only, do NOT delete/quarantine
              (so your media files are safe; you decide what to do)
        Exit codes:
          0  = clean
          2  = threat found and remediated (shouldn't happen with -DisableRemediation)
          13 = threat found, no remediation applied  ← expected threat exit code
        """
        cmd = [
            self._path,
            "-Scan",
            "-ScanType", "3",
            "-File", str(path),
            "-DisableRemediation",
        ]

        output  = ""
        threats = []
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=SCAN_TIMEOUT,
                encoding="utf-8",
                errors="replace",
            )
            output = (proc.stdout or "") + (proc.stderr or "")

            # rc 0 = clean, rc 2 or 13 = threat detected
            if proc.returncode in (2, 13):
                # Parse Defender stdout for threat name
                threats = self._parse_defender_output(output)
                if not threats:
                    # Fallback: returncode alone confirms a threat even if output is sparse
                    threats = [{"file": str(path),
                                "name": "Threat detected (see Windows Security for details)",
                                "action": "reported (no remediation)"}]
            elif proc.returncode not in (0, 2, 13) and proc.returncode is not None:
                rc_info = {
                    1:  "general error",
                    5:  "access denied — run as Administrator",
                    87: "invalid parameter",
                }
                msg = rc_info.get(proc.returncode, f"exit code {proc.returncode}")
                self._log(f"⚠   MpCmdRun: {msg}", "warn")

        except subprocess.TimeoutExpired:
            output = f"TIMEOUT after {SCAN_TIMEOUT}s"
            self._log(f"⏱   Scan timed out: {Path(path).name}", "warn")
        except Exception as exc:
            output = f"ERROR: {exc}"
            self._log(f"❌  Scan error: {exc}", "error")

        return threats, output

    def _parse_defender_output(self, text: str) -> list:
        """
        Windows Defender stdout example lines with threats:
          Threat  TrojanDropper:Win32/Agent  found.
          Threat  Virus:Win32/Sality  found.
        """
        threats = []
        for line in text.splitlines():
            stripped = line.strip()
            low = stripped.lower()
            # Primary pattern: "Threat  <Name>  found."
            if low.startswith("threat") and "found" in low:
                # Extract threat name between "Threat" and "found"
                parts = stripped.split()
                if len(parts) >= 3:
                    name = " ".join(parts[1:-1]).rstrip(".")
                else:
                    name = stripped
                threats.append({
                    "file": "(see Windows Security app for exact path)",
                    "name": name,
                    "action": "detected (no remediation)"
                })
            # Secondary: any line containing known keywords
            elif any(kw in low for kw in
                     ["trojan", "virus", "malware", "ransom", "exploit",
                      "spyware", "worm", "rootkit", "backdoor"]):
                threats.append({
                    "file": stripped[:250],
                    "name": "Detected (see full log)",
                    "action": "detected"
                })
        return self._dedup_threats(threats)

    # ── AVG Business (ashCmd.exe) ─────────────────────────────
    def _run_avg_biz(self, path: str) -> tuple:
        """
        ashCmd.exe flags (AVG Business 2019+):
          /a   all files   /c  full content   /e=100  max heuristics
          /p=2  quarantine  /t=A  all archives  /x=P  detect PUPs
          /r=~<file>  report (~ includes skipped)   /s  no sounds
        """
        try:
            REPORT_FILE.unlink(missing_ok=True)
        except Exception:
            pass

        cmd = [
            self._path, str(path),
            "/a", "/c", "/s",
            f"/r=~{REPORT_FILE}",
        ]
        if self._cfg.data.get("heuristics", True):
            cmd.append("/e=100")
        if self._cfg.data.get("scan_archives", True):
            cmd.append("/t=A")
        cmd.append("/x=P")

        return self._run_cmd_parse_report(cmd, path,
            rc_meanings={5: "access denied", 32: "file in use", 87: "invalid parameter"},
            threat_rcs={1})

    # ── AVG Legacy (avgscanx.exe) ─────────────────────────────
    def _run_avg_old(self, path: str) -> tuple:
        try:
            REPORT_FILE.unlink(missing_ok=True)
        except Exception:
            pass

        cmd = [
            self._path,
            f"/SCAN={path}",
            f"/REPORT={REPORT_FILE}",
            "/REPOK", "/REPALL",
        ]
        if self._cfg.data.get("heuristics", True):
            cmd.append("/HEUR")
        if self._cfg.data.get("scan_archives", True):
            cmd.append("/ARC")

        return self._run_cmd_parse_report(cmd, path,
            rc_meanings={5: "access denied"},
            threat_rcs={1})

    # ── shared helper ─────────────────────────────────────────
    def _run_cmd_parse_report(self, cmd, path, rc_meanings, threat_rcs) -> tuple:
        output  = ""
        threats = []
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=SCAN_TIMEOUT, encoding="utf-8", errors="replace",
            )
            output = (proc.stdout or "") + (proc.stderr or "")

            if REPORT_FILE.exists():
                report_text = REPORT_FILE.read_text(encoding="utf-8", errors="replace")
                threats.extend(self._parse_avg_report(report_text))
                try:
                    REPORT_FILE.unlink()
                except Exception:
                    pass

            threats.extend(self._parse_avg_stdout(output))
            threats = self._dedup_threats(threats)

            if proc.returncode not in threat_rcs | {0} and proc.returncode is not None:
                msg = rc_meanings.get(proc.returncode, f"exit code {proc.returncode}")
                self._log(f"⚠   Scanner: {msg}", "warn")

        except subprocess.TimeoutExpired:
            output = f"TIMEOUT after {SCAN_TIMEOUT}s"
            self._log(f"⏱   Scan timed out: {Path(path).name}", "warn")
        except Exception as exc:
            output = f"ERROR: {exc}"
            self._log(f"❌  Scan error: {exc}", "error")

        return threats, output

    def _parse_avg_report(self, text: str) -> list:
        """
        AVG report format:
          "C:/path/file.exe";"Trojan horse Xyz";"Moved to Virus Vault"
        """
        threats = []
        for line in text.splitlines():
            low = line.lower()
            if any(kw in low for kw in
                   ["trojan", "virus", "malware", "worm", "infected",
                    "threat", "suspicious", "exploit", "ransom", "spyware"]):
                parts = [p.strip().strip('"') for p in line.split(";")]
                threats.append({
                    "file":   parts[0] if parts else line[:250],
                    "name":   parts[1] if len(parts) > 1 else "Unknown",
                    "action": parts[2] if len(parts) > 2 else "detected",
                })
        return threats

    def _parse_avg_stdout(self, text: str) -> list:
        threats = []
        for line in text.splitlines():
            low = line.lower()
            if ("infected" in low or "found" in low) \
                    and "not found" not in low and "no threats" not in low:
                threats.append({
                    "file":   line[:250].strip(),
                    "name":   "Detected (see full log)",
                    "action": "detected",
                })
        return threats

    @staticmethod
    def _dedup_threats(threats: list) -> list:
        seen, out = set(), []
        for t in threats:
            key = t["file"][:200]
            if key not in seen:
                seen.add(key)
                out.append(t)
        return out


# ─────────────────────────────────────────────────────────────
# MAIN APPLICATION  (UI + orchestration)
# ─────────────────────────────────────────────────────────────
class AVGMonitorApp:

    def __init__(self):
        self._cfg      = Config()
        self._db       = Database()
        self._observer = None
        self._scanner  = None
        self._queue    = None
        self._active   = False

        # Session stats
        self._stats = {"scans": 0, "threats": 0, "clean": 0, "queued": 0}

        self._build_root()
        self._apply_style()
        self._build_ui()
        self._load_config_into_ui()

        # Pulse animation state
        self._pulse_state = 0

    # ════════════════════════════════════════════════════════
    # ROOT WINDOW
    # ════════════════════════════════════════════════════════
    def _build_root(self):
        self.root = tk.Tk()
        self.root.title("AV Folder Monitor  v1.1")
        self.root.geometry("1180x780")
        self.root.minsize(920, 620)
        self.root.configure(bg=C["bg"])
        try:
            self.root.iconbitmap(default="")
        except Exception:
            pass
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ════════════════════════════════════════════════════════
    # STYLE
    # ════════════════════════════════════════════════════════
    def _apply_style(self):
        s = ttk.Style(self.root)
        s.theme_use("clam")

        s.configure(".",
            background=C["bg"], foreground=C["text"],
            font=("Segoe UI", 10), borderwidth=0, relief="flat")

        s.configure("TFrame",       background=C["bg"])
        s.configure("TLabel",       background=C["bg"],  foreground=C["text"])
        s.configure("TLabelframe",  background=C["bg"],  foreground=C["dim"])
        s.configure("TLabelframe.Label", background=C["bg"], foreground=C["dim"],
                    font=("Segoe UI", 8, "bold"))

        s.configure("TButton",
            background=C["bg3"], foreground=C["text"],
            padding=(12, 6), font=("Segoe UI", 9))
        s.map("TButton",
            background=[("active", C["bg4"]), ("pressed", C["border"])],
            relief=[("pressed", "flat")])

        s.configure("Accent.TButton",
            background=C["accent"], foreground="white",
            font=("Segoe UI", 10, "bold"), padding=(14, 8))
        s.map("Accent.TButton",
            background=[("active", "#c42e42"), ("pressed", "#a82538")])

        s.configure("TNotebook",       background=C["bg2"], borderwidth=0)
        s.configure("TNotebook.Tab",
            background=C["bg2"], foreground=C["dim"],
            padding=(18, 8), font=("Segoe UI", 9))
        s.map("TNotebook.Tab",
            background=[("selected", C["bg3"])],
            foreground=[("selected", C["text"])])

        s.configure("Treeview",
            background=C["bg2"], foreground=C["text"],
            fieldbackground=C["bg2"], rowheight=28,
            font=("Segoe UI", 9))
        s.configure("Treeview.Heading",
            background=C["bg3"], foreground=C["dim"],
            font=("Segoe UI", 8, "bold"), relief="flat")
        s.map("Treeview",
            background=[("selected", C["bg4"])],
            foreground=[("selected", C["text"])])

        s.configure("TScrollbar",
            background=C["bg3"], troughcolor=C["bg"],
            arrowcolor=C["dim"], borderwidth=0)
        s.configure("TCombobox",
            fieldbackground=C["bg3"], background=C["bg3"],
            foreground=C["text"], selectbackground=C["bg4"],
            arrowcolor=C["dim"])
        s.configure("TSpinbox",
            fieldbackground=C["bg3"], background=C["bg3"],
            foreground=C["text"], arrowcolor=C["dim"])
        s.configure("TCheckbutton",
            background=C["bg2"], foreground=C["text"])

    # ════════════════════════════════════════════════════════
    # UI ASSEMBLY
    # ════════════════════════════════════════════════════════
    def _build_ui(self):
        self._build_header()
        self._build_body()
        self._build_statusbar()

    # ── HEADER ───────────────────────────────────────────────
    def _build_header(self):
        hdr = tk.Frame(self.root, bg=C["bg3"], height=58)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        # Logo
        tk.Label(hdr, text="🛡", bg=C["bg3"], fg=C["accent"],
                 font=("Segoe UI", 22)).pack(side="left", padx=(18, 4), pady=8)
        tk.Label(hdr, text="AV Folder Monitor", bg=C["bg3"], fg=C["text"],
                 font=("Segoe UI", 15, "bold")).pack(side="left", pady=8)
        tk.Label(hdr, text="v1.1", bg=C["bg3"], fg=C["dim"],
                 font=("Segoe UI", 9)).pack(side="left", padx=(6, 0), pady=(18, 0))

        # Right side controls
        self._btn_toggle = ttk.Button(hdr, text="▶  Start Monitoring",
                                      style="Accent.TButton",
                                      command=self._toggle_monitoring)
        self._btn_toggle.pack(side="right", padx=16, pady=10)

        # Status pill
        pill = tk.Frame(hdr, bg=C["bg3"])
        pill.pack(side="right", padx=8)
        self._dot_lbl = tk.Label(pill, text="●", bg=C["bg3"], fg=C["dim"],
                                 font=("Segoe UI", 16))
        self._dot_lbl.pack(side="left")
        self._state_lbl = tk.Label(pill, text="STOPPED", bg=C["bg3"], fg=C["dim"],
                                   font=("Segoe UI", 9, "bold"))
        self._state_lbl.pack(side="left", padx=4)

    # ── BODY ─────────────────────────────────────────────────
    def _build_body(self):
        pane = ttk.PanedWindow(self.root, orient="horizontal")
        pane.pack(fill="both", expand=True)

        # LEFT
        left = tk.Frame(pane, bg=C["bg2"], width=310)
        left.pack_propagate(False)
        pane.add(left, weight=0)
        self._build_left(left)

        # RIGHT
        right = tk.Frame(pane, bg=C["bg"])
        pane.add(right, weight=1)
        self._build_right(right)

    # ── LEFT PANEL ───────────────────────────────────────────
    def _build_left(self, parent):
        # ── Folders ─────────────────────────────────────────
        self._section_label(parent, "WATCHED FOLDERS")

        self._folder_vars    = []
        self._folder_st_lbls = []

        for i in range(3):
            outer = tk.Frame(parent, bg=C["bg2"])
            outer.pack(fill="x", padx=12, pady=3)

            # Number badge
            badge = tk.Frame(outer, bg=C["blue"], width=24, height=24)
            badge.pack(side="left", padx=(0, 7))
            badge.pack_propagate(False)
            tk.Label(badge, text=str(i + 1), bg=C["blue"], fg="white",
                     font=("Segoe UI", 9, "bold")).place(relx=.5, rely=.5, anchor="center")

            col = tk.Frame(outer, bg=C["bg2"])
            col.pack(side="left", fill="x", expand=True)

            row = tk.Frame(col, bg=C["bg2"])
            row.pack(fill="x")

            var = tk.StringVar()
            self._folder_vars.append(var)

            ent = tk.Entry(row, textvariable=var, bg=C["bg4"], fg=C["text"],
                           relief="flat", font=("Segoe UI", 9),
                           insertbackground=C["text"], bd=0)
            ent.pack(side="left", fill="x", expand=True, ipady=5, padx=(0, 3))

            tk.Button(row, text="…", bg=C["bg3"], fg=C["dim"],
                      relief="flat", font=("Segoe UI", 9), width=3,
                      activebackground=C["bg4"], activeforeground=C["text"],
                      cursor="hand2",
                      command=lambda idx=i: self._browse_folder(idx)
                      ).pack(side="right")

            st = tk.Label(col, text="Not configured", bg=C["bg2"], fg=C["dim"],
                          font=("Segoe UI", 8))
            st.pack(anchor="w")
            self._folder_st_lbls.append(st)

        # ── Separator ───────────────────────────────────────
        self._separator(parent)
        self._section_label(parent, "SCANNER SETTINGS")

        avg_frame = tk.Frame(parent, bg=C["bg2"])
        avg_frame.pack(fill="x", padx=12, pady=3)

        tk.Label(avg_frame, text="Scanner path  (MpCmdRun.exe or ashCmd.exe)",
                 bg=C["bg2"], fg=C["dim"], font=("Segoe UI", 8)).pack(anchor="w")

        avg_row = tk.Frame(avg_frame, bg=C["bg2"])
        avg_row.pack(fill="x")

        self._avg_var = tk.StringVar()
        tk.Entry(avg_row, textvariable=self._avg_var, bg=C["bg4"], fg=C["text"],
                 relief="flat", font=("Segoe UI", 8),
                 insertbackground=C["text"]).pack(side="left", fill="x", expand=True, ipady=4)
        tk.Button(avg_row, text="…", bg=C["bg3"], fg=C["dim"], relief="flat",
                  font=("Segoe UI", 9), width=3,
                  activebackground=C["bg4"], activeforeground=C["text"],
                  cursor="hand2", command=self._browse_avg).pack(side="right", padx=(3, 0))

        self._avg_status_lbl = tk.Label(parent, text="", bg=C["bg2"],
                                        font=("Segoe UI", 8))
        self._avg_status_lbl.pack(anchor="w", padx=16, pady=(2, 0))

        # ── Scan options ────────────────────────────────────
        opt_frame = tk.Frame(parent, bg=C["bg2"])
        opt_frame.pack(fill="x", padx=12, pady=(8, 4))

        row_d = tk.Frame(opt_frame, bg=C["bg2"])
        row_d.pack(fill="x", pady=2)
        tk.Label(row_d, text="Scan delay (sec):", bg=C["bg2"], fg=C["dim"],
                 font=("Segoe UI", 9)).pack(side="left")
        self._debounce_var = tk.IntVar(value=DEFAULT_DEBOUNCE)
        ttk.Spinbox(row_d, from_=1, to=60, width=5,
                    textvariable=self._debounce_var,
                    font=("Segoe UI", 9)).pack(side="right")

        self._heur_var = tk.BooleanVar(value=True)
        self._arc_var  = tk.BooleanVar(value=True)

        for var, label in [(self._heur_var, "Heuristic analysis"),
                           (self._arc_var,  "Scan inside archives")]:
            cb = tk.Checkbutton(opt_frame, text=label, variable=var,
                                bg=C["bg2"], fg=C["text"], selectcolor=C["bg4"],
                                activebackground=C["bg2"], activeforeground=C["text"],
                                font=("Segoe UI", 9), relief="flat", bd=0)
            cb.pack(anchor="w")

        # ── Save ────────────────────────────────────────────
        self._separator(parent)
        ttk.Button(parent, text="💾  Save Settings",
                   command=self._save_settings).pack(fill="x", padx=12, pady=4)

        # ── Stats ───────────────────────────────────────────
        self._separator(parent)
        self._section_label(parent, "SESSION STATISTICS")

        self._stat_lbls = {}
        for key, label in [
            ("scans",   "Total Scans"),
            ("clean",   "Clean"),
            ("threats", "Threats Found"),
            ("queued",  "In Queue"),
        ]:
            r = tk.Frame(parent, bg=C["bg2"])
            r.pack(fill="x", padx=16, pady=1)
            tk.Label(r, text=label, bg=C["bg2"], fg=C["dim"],
                     font=("Segoe UI", 9)).pack(side="left")
            v = tk.Label(r, text="0", bg=C["bg2"], fg=C["text"],
                         font=("Segoe UI", 9, "bold"))
            v.pack(side="right")
            self._stat_lbls[key] = v

    def _section_label(self, parent, text):
        tk.Label(parent, text=text, bg=C["bg2"], fg=C["dim"],
                 font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=16, pady=(10, 3))

    def _separator(self, parent):
        tk.Frame(parent, bg=C["border"], height=1).pack(fill="x", padx=12, pady=6)

    # ── RIGHT PANEL ──────────────────────────────────────────
    def _build_right(self, parent):
        # Current scan banner
        banner = tk.Frame(parent, bg=C["bg2"], height=52)
        banner.pack(fill="x")
        banner.pack_propagate(False)

        self._banner_lbl = tk.Label(
            banner,
            text="⏸   Monitoring is stopped  —  configure folders and press Start",
            bg=C["bg2"], fg=C["dim"], font=("Segoe UI", 10), anchor="w"
        )
        self._banner_lbl.pack(side="left", padx=16, fill="y")

        # Right side toolbar
        ttk.Button(banner, text="🗑  Clear Log",
                   command=self._clear_log).pack(side="right", padx=6, pady=10)
        ttk.Button(banner, text="🔍  Manual Scan",
                   command=self._manual_scan).pack(side="right", padx=6, pady=10)

        # ── Notebook ────────────────────────────────────────
        self._nb = ttk.Notebook(parent)
        self._nb.pack(fill="both", expand=True)

        log_tab  = tk.Frame(self._nb, bg=C["bg"])
        hist_tab = tk.Frame(self._nb, bg=C["bg"])
        thr_tab  = tk.Frame(self._nb, bg=C["bg"])

        self._nb.add(log_tab,  text="  📋  Live Log  ")
        self._nb.add(hist_tab, text="  🕐  Scan History  ")
        self._nb.add(thr_tab,  text="  🚨  Threats  ")

        self._build_log_tab(log_tab)
        self._build_history_tab(hist_tab)
        self._build_threats_tab(thr_tab)

    # ── LOG TAB ──────────────────────────────────────────────
    def _build_log_tab(self, parent):
        self._log_text = tk.Text(
            parent, bg="#080c14", fg=C["text"],
            font=("Consolas", 10), relief="flat",
            state="disabled", wrap="word",
            insertbackground=C["text"],
            selectbackground=C["bg4"],
            padx=8, pady=4
        )
        for tag, color in LOG_TAGS.items():
            self._log_text.tag_configure(tag, foreground=color)
        self._log_text.tag_configure("ts", foreground=LOG_TAGS["ts"])

        vsb = ttk.Scrollbar(parent, orient="vertical", command=self._log_text.yview)
        self._log_text.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._log_text.pack(fill="both", expand=True)

        self._log("🛡   AVG Folder Monitor initialised", "info")
        self._log("     Configure folders on the left and press  ▶ Start Monitoring", "path")

    # ── HISTORY TAB ──────────────────────────────────────────
    def _build_history_tab(self, parent):
        toolbar = tk.Frame(parent, bg=C["bg"])
        toolbar.pack(fill="x", padx=8, pady=4)

        ttk.Button(toolbar, text="🔄 Refresh",      command=self._refresh_history).pack(side="left", padx=3)
        ttk.Button(toolbar, text="🗑 Clear History", command=self._clear_history).pack(side="left", padx=3)

        tk.Label(toolbar, text="Show:", bg=C["bg"], fg=C["dim"],
                 font=("Segoe UI", 9)).pack(side="right", padx=4)
        self._hist_filter = tk.StringVar(value="All")
        self._hist_filter.trace_add("write", lambda *_: self._refresh_history())
        ttk.Combobox(toolbar, textvariable=self._hist_filter, state="readonly",
                     values=["All", "Clean", "Threats Found", "Error"],
                     width=15).pack(side="right", padx=4)

        cols = ("ts", "trigger", "paths", "status", "threats", "dur")
        self._hist_tree = ttk.Treeview(parent, columns=cols, show="headings")

        for col, hdr, w, anchor in [
            ("ts",      "Time",           140, "w"),
            ("trigger", "Trigger",        200, "w"),
            ("paths",   "Paths Scanned",   95, "center"),
            ("status",  "Result",         110, "center"),
            ("threats", "Threats",         70, "center"),
            ("dur",     "Duration",        80, "center"),
        ]:
            self._hist_tree.heading(col, text=hdr,
                                    command=lambda c=col: self._sort_history(c))
            self._hist_tree.column(col, width=w, anchor=anchor, minwidth=50)

        self._hist_tree.tag_configure("threat_row", foreground=C["red"])
        self._hist_tree.tag_configure("clean_row",  foreground=C["green"])
        self._hist_tree.tag_configure("error_row",  foreground=C["yellow"])

        vsb = ttk.Scrollbar(parent, orient="vertical",   command=self._hist_tree.yview)
        hsb = ttk.Scrollbar(parent, orient="horizontal", command=self._hist_tree.xview)
        self._hist_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        hsb.pack(side="bottom", fill="x")
        vsb.pack(side="right",  fill="y")
        self._hist_tree.pack(fill="both", expand=True, padx=8, pady=(0, 4))
        self._hist_tree.bind("<Double-1>", self._show_scan_detail)

        self._refresh_history()

    # ── THREATS TAB ──────────────────────────────────────────
    def _build_threats_tab(self, parent):
        toolbar = tk.Frame(parent, bg=C["bg"])
        toolbar.pack(fill="x", padx=8, pady=4)

        ttk.Button(toolbar, text="🔄 Refresh", command=self._refresh_threats).pack(side="left", padx=3)
        tk.Label(toolbar,
                 text="All detected threats — across all scan sessions",
                 bg=C["bg"], fg=C["dim"], font=("Segoe UI", 9)).pack(side="left", padx=12)

        cols = ("ts", "file", "name", "action")
        self._thr_tree = ttk.Treeview(parent, columns=cols, show="headings")

        for col, hdr, w, anchor in [
            ("ts",     "Detected At",  140, "w"),
            ("file",   "File Path",    420, "w"),
            ("name",   "Threat",       200, "w"),
            ("action", "Action",       100, "center"),
        ]:
            self._thr_tree.heading(col, text=hdr)
            self._thr_tree.column(col, width=w, anchor=anchor, minwidth=50)

        self._thr_tree.tag_configure("trow", foreground=C["red"])

        vsb = ttk.Scrollbar(parent, orient="vertical",   command=self._thr_tree.yview)
        hsb = ttk.Scrollbar(parent, orient="horizontal", command=self._thr_tree.xview)
        self._thr_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        hsb.pack(side="bottom", fill="x")
        vsb.pack(side="right",  fill="y")
        self._thr_tree.pack(fill="both", expand=True, padx=8, pady=(0, 4))

        self._refresh_threats()

    # ── STATUS BAR ───────────────────────────────────────────
    def _build_statusbar(self):
        bar = tk.Frame(self.root, bg=C["bg3"], height=22)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)

        self._sb_left = tk.Label(bar, text="Ready", bg=C["bg3"], fg=C["dim"],
                                  font=("Segoe UI", 8))
        self._sb_left.pack(side="left", padx=10)

        self._sb_right = tk.Label(bar, text="", bg=C["bg3"], fg=C["dim"],
                                   font=("Segoe UI", 8))
        self._sb_right.pack(side="right", padx=10)

    # ════════════════════════════════════════════════════════
    # CONFIG ↔ UI
    # ════════════════════════════════════════════════════════
    def _load_config_into_ui(self):
        for i, path in enumerate(self._cfg.data["folders"][:3]):
            self._folder_vars[i].set(path)
            self._update_folder_status(i)
        self._avg_var.set(self._cfg.data.get("scanner_path", ""))
        self._debounce_var.set(self._cfg.data.get("debounce", DEFAULT_DEBOUNCE))
        self._heur_var.set(self._cfg.data.get("heuristics", True))
        self._arc_var.set(self._cfg.data.get("scan_archives", True))
        self._update_scanner_status()

    def _save_settings(self):
        self._cfg.data["folders"]       = [v.get().strip() for v in self._folder_vars]
        self._cfg.data["scanner_path"]  = self._avg_var.get().strip()
        self._cfg.data["debounce"]      = self._debounce_var.get()
        self._cfg.data["heuristics"]    = self._heur_var.get()
        self._cfg.data["scan_archives"] = self._arc_var.get()
        self._cfg.save()
        for i in range(3):
            self._update_folder_status(i)
        self._update_scanner_status()
        self._sb_left.config(text="✓ Settings saved", fg=C["green"])
        self.root.after(3000, lambda: self._sb_left.config(text="Ready", fg=C["dim"]))
        self._log("💾  Settings saved", "info")

    def _update_folder_status(self, idx):
        path = self._folder_vars[idx].get().strip()
        lbl  = self._folder_st_lbls[idx]
        if not path:
            lbl.config(text="Not configured", fg=C["dim"])
        elif Path(path).exists():
            lbl.config(text=f"✓  Exists", fg=C["green"])
        else:
            lbl.config(text="⚠  Path not found", fg=C["red"])

    def _update_scanner_status(self):
        path = self._avg_var.get().strip()
        if path and Path(path).exists():
            eng = Config.engine_type(path)
            label = {"defender": "Windows Defender  (MpCmdRun.exe)",
                     "avg_biz":  "AVG Business  (ashCmd.exe)",
                     "avg_old":  "AVG Legacy  (avgscanx.exe)"}.get(eng, Path(path).name)
            self._avg_status_lbl.config(text=f"✓  {label}", fg=C["green"])
        elif path:
            self._avg_status_lbl.config(text="⚠  File not found at this path", fg=C["red"])
        else:
            self._avg_status_lbl.config(text="⚠  Not configured", fg=C["yellow"])

    # ════════════════════════════════════════════════════════
    # BROWSE DIALOGS
    # ════════════════════════════════════════════════════════
    def _browse_folder(self, idx):
        path = filedialog.askdirectory(title=f"Select Folder {idx + 1} to Monitor")
        if path:
            self._folder_vars[idx].set(path)
            self._update_folder_status(idx)

    def _browse_avg(self):
        path = filedialog.askopenfilename(
            title="Locate scanner  (MpCmdRun.exe / ashCmd.exe / avgscanx.exe)",
            filetypes=[("Windows Defender", "MpCmdRun.exe"),
                       ("AVG Business",     "ashCmd.exe"),
                       ("AVG Legacy",       "avgscanx.exe"),
                       ("Executable",       "*.exe"),
                       ("All",              "*.*")]
        )
        if path:
            self._avg_var.set(path)
            self._update_scanner_status()

    # ════════════════════════════════════════════════════════
    # MONITORING CONTROL
    # ════════════════════════════════════════════════════════
    def _toggle_monitoring(self):
        if self._active:
            self._stop()
        else:
            self._start()

    def _start(self):
        self._save_settings()

        folders = [f for f in self._cfg.data["folders"] if f and Path(f).exists()]
        if not folders:
            messagebox.showwarning("No Folders", "Please configure at least one valid folder first.")
            return

        avg_ok = self._cfg.data["scanner_path"] and \
                 Path(self._cfg.data["scanner_path"]).exists()
        if not avg_ok:
            if not messagebox.askyesno(
                "Scanner Not Found",
                "No antivirus scanner found.\n\n"
                "The monitor will detect new files but cannot scan them.\n"
                "Windows Defender (MpCmdRun.exe) should be at:\n"
                "  C:\\Program Files\\Windows Defender\\MpCmdRun.exe\n\n"
                "Continue watching folders without scanning?"
            ):
                return

        # Wire up components
        self._queue = SmartScanQueue(
            on_ready=self._on_scan_ready,
            on_queued_change=self._on_queued_change,
            debounce_sec=self._cfg.data.get("debounce", DEFAULT_DEBOUNCE)
        )
        self._scanner = AntivirusScanner(
            scanner_path=self._cfg.data["scanner_path"],
            log_fn=self._log,
            db=self._db,
            cfg=self._cfg
        )

        handler = MediaHandler(self._queue, self._log)
        self._observer = Observer()
        for folder in folders:
            self._observer.schedule(handler, folder, recursive=True)
            self._log(f"👁   Watching: {folder}", "info")

        self._observer.start()
        self._active = True

        self._btn_toggle.config(text="⏹  Stop Monitoring")
        self._dot_lbl.config(fg=C["green"])
        self._state_lbl.config(text="MONITORING", fg=C["green"])
        self._banner_lbl.config(
            text=f"✅   Monitoring {len(folders)} folder(s)  —  waiting for new files…",
            fg=C["green"]
        )
        self._log(f"🚀  Monitoring started  ({len(folders)} folder(s))", "ok")
        self._pulse()

    def _stop(self):
        if self._observer:
            self._observer.stop()
            self._observer.join()
            self._observer = None
        self._active = False

        self._btn_toggle.config(text="▶  Start Monitoring")
        self._dot_lbl.config(fg=C["dim"])
        self._state_lbl.config(text="STOPPED", fg=C["dim"])
        self._banner_lbl.config(
            text="⏸   Monitoring stopped",
            fg=C["dim"]
        )
        self._log("⏹   Monitoring stopped", "warn")

    # ════════════════════════════════════════════════════════
    # SCAN FLOW
    # ════════════════════════════════════════════════════════
    def _on_scan_ready(self, paths: list):
        """Called by SmartScanQueue from its timer thread."""
        if not paths:
            self._queue.scan_done()
            return

        trigger = paths[0]
        self._stats["scans"] += 1

        # Update banner (main thread)
        self.root.after(0, lambda: self._set_scanning_ui(paths))

        def _worker():
            try:
                result = self._scanner.scan(paths, trigger)
                if result["threats"] > 0:
                    self._stats["threats"] += result["threats"]
                    self.root.after(0, self._refresh_threats)
                    self.root.after(0, lambda: self._alert_threats(result["threats"]))
                else:
                    self._stats["clean"] += 1
            finally:
                self._queue.scan_done()
                self.root.after(0, self._set_idle_ui)
                self.root.after(0, self._refresh_history)
                self.root.after(0, self._redraw_stats)

        threading.Thread(target=_worker, daemon=True, name="ScanWorker").start()

    def _on_queued_change(self, count: int):
        self._stats["queued"] = count
        self.root.after(0, self._redraw_stats)
        self.root.after(0, lambda: self._sb_right.config(
            text=f"Queue: {count}" if count else ""
        ))

    def _set_scanning_ui(self, paths: list):
        self._dot_lbl.config(fg=C["yellow"])
        self._state_lbl.config(text="SCANNING", fg=C["yellow"])
        names = ", ".join(Path(p).name for p in paths[:2])
        if len(paths) > 2:
            names += f"  +{len(paths) - 2} more"
        self._banner_lbl.config(
            text=f"🔍   Scanning: {names}",
            fg=C["yellow"]
        )

    def _set_idle_ui(self):
        if self._active:
            self._dot_lbl.config(fg=C["green"])
            self._state_lbl.config(text="MONITORING", fg=C["green"])
            self._banner_lbl.config(
                text="✅   Monitoring active  —  waiting for new files…",
                fg=C["green"]
            )

    def _alert_threats(self, count: int):
        self._nb.select(2)   # Switch to Threats tab
        messagebox.showwarning(
            "⚠️  Threat Detected!",
            f"AVG detected {count} threat(s)!\nSee the Threats tab for details."
        )

    def _manual_scan(self):
        path = filedialog.askdirectory(title="Select folder to scan manually")
        if not path:
            return
        self._log(f"🔍  Manual scan queued: {path}", "info")
        if self._queue:
            self._queue.add(path)
        else:
            sp = self._cfg.data.get("scanner_path", "")
            if not sp or not Path(sp).exists():
                messagebox.showwarning("Scanner Not Set",
                    "Please configure the scanner path first and press Start.")
                return
            sc = AntivirusScanner(sp, self._log, self._db, self._cfg)
            threading.Thread(target=lambda: sc.scan([path], path), daemon=True).start()

    # ════════════════════════════════════════════════════════
    # PULSE ANIMATION
    # ════════════════════════════════════════════════════════
    def _pulse(self):
        if not self._active:
            return
        colors = [C["green"], "#2eb870", "#1f9457", C["green"]]
        self._dot_lbl.config(fg=colors[self._pulse_state % len(colors)])
        self._pulse_state += 1
        self.root.after(600, self._pulse)

    # ════════════════════════════════════════════════════════
    # LOG
    # ════════════════════════════════════════════════════════
    def _log(self, msg: str, tag: str = "info"):
        def _do():
            self._log_text.config(state="normal")
            ts = datetime.now().strftime("%H:%M:%S")
            self._log_text.insert("end", f"[{ts}]  ", "ts")
            self._log_text.insert("end", msg + "\n", tag)
            self._log_text.see("end")
            self._log_text.config(state="disabled")

        if threading.current_thread() is threading.main_thread():
            _do()
        else:
            self.root.after(0, _do)

    def _clear_log(self):
        self._log_text.config(state="normal")
        self._log_text.delete("1.0", "end")
        self._log_text.config(state="disabled")
        self._log("Log cleared", "info")

    # ════════════════════════════════════════════════════════
    # STATS
    # ════════════════════════════════════════════════════════
    def _redraw_stats(self):
        for key, lbl in self._stat_lbls.items():
            val = self._stats.get(key, 0)
            color = C["red"] if key == "threats" and val > 0 else C["text"]
            lbl.config(text=str(val), fg=color)

    # ════════════════════════════════════════════════════════
    # HISTORY TABLE
    # ════════════════════════════════════════════════════════
    def _refresh_history(self, *_):
        for item in self._hist_tree.get_children():
            self._hist_tree.delete(item)

        flt = self._hist_filter.get()
        status_map = {
            "Clean":         "clean",
            "Threats Found": "threats_found",
            "Error":         "error",
        }
        db_filter = status_map.get(flt)

        for row in self._db.get_scans(status_filter=db_filter):
            id_, ts, trigger, scan_paths, status, threats, dur, _log = row
            try:
                n_paths = len(json.loads(scan_paths))
            except Exception:
                n_paths = "?"

            ts_s     = (ts or "")[:16].replace("T", " ")
            trig_s   = Path(trigger).name if trigger else "manual"
            dur_s    = f"{dur:.1f}s" if dur else "—"
            stat_s   = ("🚨 THREAT" if status == "threats_found"
                        else ("✅ Clean" if status == "clean" else "❌ Error"))
            row_tag  = ("threat_row" if status == "threats_found"
                        else ("error_row" if status == "error" else "clean_row"))

            self._hist_tree.insert("", "end", iid=str(id_),
                                   values=(ts_s, trig_s, n_paths, stat_s, threats or 0, dur_s),
                                   tags=(row_tag,))

    def _sort_history(self, col):
        # Simple toggle sort
        items = [(self._hist_tree.set(k, col), k) for k in self._hist_tree.get_children("")]
        items.sort(reverse=True)
        for idx, (_, k) in enumerate(items):
            self._hist_tree.move(k, "", idx)

    def _show_scan_detail(self, _event):
        sel = self._hist_tree.selection()
        if not sel:
            return
        row = self._db.get_scan_by_id(int(sel[0]))
        if not row:
            return
        id_, ts, trigger, scan_paths, status, threats, dur, raw_log = row

        win = tk.Toplevel(self.root)
        win.title(f"Scan #{id_}  Detail")
        win.geometry("720x520")
        win.configure(bg=C["bg"])

        hdr = tk.Frame(win, bg=C["bg3"])
        hdr.pack(fill="x")

        stat_color = C["red"] if status == "threats_found" else C["green"]
        tk.Label(hdr,
                 text=f"  Scan #{id_}   {(ts or '')[:16].replace('T',' ')}   "
                      f"{threats} threat(s)   {f'{dur:.1f}s' if dur else ''}",
                 bg=C["bg3"], fg=stat_color,
                 font=("Segoe UI", 10, "bold")).pack(side="left", padx=12, pady=10)

        txt = scrolledtext.ScrolledText(
            win, bg="#080c14", fg=C["text"],
            font=("Consolas", 9), relief="flat", padx=8, pady=4
        )
        txt.pack(fill="both", expand=True, padx=8, pady=8)

        try:
            paths_list = json.loads(scan_paths)
            txt.insert("end", "SCANNED PATHS\n" + "─" * 60 + "\n")
            for p in paths_list:
                txt.insert("end", f"  • {p}\n")
            txt.insert("end", "\nAVG OUTPUT\n" + "─" * 60 + "\n")
        except Exception:
            pass

        txt.insert("end", raw_log or "(no output captured)")
        txt.config(state="disabled")

    # ════════════════════════════════════════════════════════
    # THREATS TABLE
    # ════════════════════════════════════════════════════════
    def _refresh_threats(self):
        for item in self._thr_tree.get_children():
            self._thr_tree.delete(item)
        for row in self._db.get_threats():
            id_, scan_id, ts, fp, name, action = row
            ts_s = (ts or "")[:16].replace("T", " ")
            self._thr_tree.insert("", "end",
                                  values=(ts_s, fp, name or "Unknown", action or "detected"),
                                  tags=("trow",))
        # Update tab badge
        count = len(self._thr_tree.get_children())
        badge = f"  🚨  Threats ({count})  " if count else "  🚨  Threats  "
        self._nb.tab(2, text=badge)

    # ════════════════════════════════════════════════════════
    # HISTORY CLEAR
    # ════════════════════════════════════════════════════════
    def _clear_history(self):
        if messagebox.askyesno("Clear History",
                                "Delete all scan history and threats? This cannot be undone."):
            self._db.clear_all()
            self._refresh_history()
            self._refresh_threats()
            self._log("🗑   History cleared", "warn")

    # ════════════════════════════════════════════════════════
    # CLOSE
    # ════════════════════════════════════════════════════════
    def _on_close(self):
        if self._active:
            self._stop()
        self.root.destroy()

    # ════════════════════════════════════════════════════════
    # ENTRY
    # ════════════════════════════════════════════════════════
    def run(self):
        self.root.mainloop()


# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    AVGMonitorApp().run()
