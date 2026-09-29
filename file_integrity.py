# file_integrity_monitor.py
import hashlib
import json
import stat
import time
import fnmatch
import argparse
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor
from enum import Enum
from typing import Iterator

# ── Constants ─────────────────────────────────────────────────────────

DEFAULT_BASELINE  = "baseline.json"
DEFAULT_ALGORITHM = "sha256"
CHUNK_SIZE        = 65536   # 64 KB
DEFAULT_THREADS   = 8
DEFAULT_POLL_SECS = 30
SUPPORTED_ALGORITHMS = {"sha256", "sha512", "blake2b"}

# ── Enums ─────────────────────────────────────────────────────────────

class Status(Enum):
    OK       = "OK"
    MODIFIED = "MODIFIED"
    MISSING  = "MISSING"
    NEW      = "NEW"

# ── Data ──────────────────────────────────────────────────────────────

@dataclass
class FileMeta:
    """Hash + OS metadata captured in a single stat+read pass."""
    path:        str
    hash:        str
    size:        int
    mtime:       float
    permissions: str   # e.g. "0o644"

    def to_dict(self) -> dict:
        return {"hash": self.hash, "size": self.size,
                "mtime": self.mtime, "permissions": self.permissions}

    @staticmethod
    def from_dict(path: str, d: dict) -> "FileMeta":
        return FileMeta(path=path, hash=d["hash"], size=d.get("size", 0),
                        mtime=d.get("mtime", 0.0), permissions=d.get("permissions", "?"))

@dataclass
class FileChange:
    path:   str
    status: Status
    detail: str = ""   # human-readable description of what changed

@dataclass
class IntegrityReport:
    folder:      str
    baseline_at: str
    checked_at:  str
    algorithm:   str
    changes:     list[FileChange] = field(default_factory=list)
    skipped:     list[str]        = field(default_factory=list)

    # ── Views ──

    @property
    def ok(self)       -> list[FileChange]: return [c for c in self.changes if c.status == Status.OK]
    @property
    def modified(self) -> list[FileChange]: return [c for c in self.changes if c.status == Status.MODIFIED]
    @property
    def missing(self)  -> list[FileChange]: return [c for c in self.changes if c.status == Status.MISSING]
    @property
    def new(self)      -> list[FileChange]: return [c for c in self.changes if c.status == Status.NEW]

    @property
    def severity(self) -> str:
        if self.modified or self.missing: return "CRITICAL"
        if self.new:                      return "WARNING"
        return "OK"

    # ── Display ──

    def display(self, show_ok: bool = False) -> None:
        w = 66
        _icons = {Status.MODIFIED: "⚠️  [MODIFIED]",
                  Status.MISSING:  "❌  [MISSING] ",
                  Status.NEW:      "🆕  [NEW]     ",
                  Status.OK:       "✅  [OK]      "}

        print(f"\n{'─'*w}")
        print(f"  File Integrity Report")
        print(f"  Folder    : {self.folder}")
        print(f"  Baseline  : {self.baseline_at}")
        print(f"  Checked   : {self.checked_at}")
        print(f"  Algorithm : {self.algorithm.upper()}")
        print(f"{'─'*w}\n")

        for c in self.changes:
            if c.status == Status.OK and not show_ok:
                continue
            detail = f"  ← {c.detail}" if c.detail else ""
            print(f"  {_icons[c.status]}  {c.path}{detail}")

        if self.skipped:
            print(f"\n  ⏭  {len(self.skipped)} file(s) skipped (permission denied or excluded)")

        sev_icon = {"CRITICAL": "🔴", "WARNING": "⚠️ ", "OK": "✅"}[self.severity]
        print(f"\n{'─'*w}")
        print(f"  {sev_icon} Severity : {self.severity}")
        print(f"  ok={len(self.ok)}  modified={len(self.modified)}  "
              f"missing={len(self.missing)}  new={len(self.new)}  skipped={len(self.skipped)}")
        print(f"{'─'*w}\n")

    def to_dict(self) -> dict:
        return {
            "folder": self.folder, "baseline_at": self.baseline_at,
            "checked_at": self.checked_at, "algorithm": self.algorithm,
            "severity": self.severity,
            "summary": {"ok": len(self.ok), "modified": len(self.modified),
                        "missing": len(self.missing), "new": len(self.new),
                        "skipped": len(self.skipped)},
            "changes": [{"path": c.path, "status": c.status.value, "detail": c.detail}
                        for c in self.changes if c.status != Status.OK],
            "skipped": self.skipped,
        }

    def save(self, path: str) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2))
        print(f"  Report saved → '{path}'")

# ── Hashing ───────────────────────────────────────────────────────────

def _make_hasher(algorithm: str):
    return hashlib.blake2b() if algorithm == "blake2b" else hashlib.new(algorithm)

def hash_file(filepath: Path, algorithm: str = DEFAULT_ALGORITHM) -> str:
    h = _make_hasher(algorithm)
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()

def _get_meta(filepath: Path, relative: str, algorithm: str) -> FileMeta:
    """Hash + stat in one pass — avoids a second open() for metadata."""
    st = filepath.stat()
    return FileMeta(
        path=relative,
        hash=hash_file(filepath, algorithm),
        size=st.st_size,
        mtime=st.st_mtime,
        permissions=oct(stat.S_IMODE(st.st_mode)),
    )

# ── File walking ──────────────────────────────────────────────────────

def _walk(folder: Path, exclude: list[str],
          baseline_path: Path) -> Iterator[tuple[Path, str]]:
    """Yield (abs_path, rel_path) for every non-excluded, non-baseline file."""
    for filepath in sorted(folder.rglob("*")):
        if not filepath.is_file():
            continue
        if filepath.resolve() == baseline_path.resolve():
            continue
        relative = str(filepath.relative_to(folder))
        if any(fnmatch.fnmatch(relative, pat) for pat in exclude):
            continue
        yield filepath, relative

# ── Concurrent scanning ───────────────────────────────────────────────

def _scan_all(
    files:     list[tuple[Path, str]],
    algorithm: str,
    threads:   int,
) -> tuple[dict[str, FileMeta], list[str]]:
    """Hash every file in parallel. Returns (results, skipped_paths)."""
    results: dict[str, FileMeta] = {}
    skipped: list[str]           = []

    def _scan(item: tuple[Path, str]):
        filepath, relative = item
        try:
            return relative, _get_meta(filepath, relative, algorithm)
        except PermissionError:
            return relative, None

    with ThreadPoolExecutor(max_workers=threads) as pool:
        for relative, meta in pool.map(_scan, files):
            if meta is None:
                skipped.append(relative)
            else:
                results[relative] = meta

    return results, skipped

# ── Baseline ──────────────────────────────────────────────────────────

def create_baseline(
    folder:        str,
    baseline_path: str       = DEFAULT_BASELINE,
    algorithm:     str       = DEFAULT_ALGORITHM,
    exclude:       list[str] | None = None,
    threads:       int       = DEFAULT_THREADS,
) -> None:
    """
    Scan a folder concurrently and write hash + metadata baseline to JSON.

    Args:
        folder:        Folder to monitor.
        baseline_path: Where to write the baseline JSON.
        algorithm:     sha256 | sha512 | blake2b
        exclude:       Glob patterns to skip, e.g. ["*.log", ".git/*"]
        threads:       Thread-pool size for concurrent hashing.
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm '{algorithm}'. Use: {SUPPORTED_ALGORITHMS}")

    folder_p   = Path(folder).resolve()
    baseline_p = Path(baseline_path).resolve()
    exclude    = exclude or []

    files = list(_walk(folder_p, exclude, baseline_p))
    print(f"  Hashing {len(files)} file(s) with {threads} thread(s) [{algorithm.upper()}]…")

    results, skipped = _scan_all(files, algorithm, threads)

    data = {
        "folder":     str(folder_p),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "algorithm":  algorithm,
        "exclude":    exclude,
        "files":      {rel: meta.to_dict() for rel, meta in results.items()},
    }
    baseline_p.write_text(json.dumps(data, indent=2))

    print(f"  ✅ Baseline saved → '{baseline_p}'")
    print(f"     {len(results)} hashed  |  {len(skipped)} skipped")

# ── Integrity check ───────────────────────────────────────────────────

def check_integrity(
    folder:        str,
    baseline_path: str       = DEFAULT_BASELINE,
    exclude:       list[str] | None = None,
    threads:       int       = DEFAULT_THREADS,
) -> IntegrityReport:
    """
    Compare current folder state to the stored baseline.
    Extra exclude patterns are merged with those stored in the baseline.
    """
    baseline_p = Path(baseline_path).resolve()
    if not baseline_p.exists():
        raise FileNotFoundError(f"No baseline at '{baseline_p}'. Run 'create' first.")

    data        = json.loads(baseline_p.read_text())
    algorithm   = data.get("algorithm", DEFAULT_ALGORITHM)
    baseline_at = data.get("created_at", "unknown")
    stored: dict[str, dict] = data["files"]

    folder_p = Path(folder).resolve()
    exclude  = list(set((exclude or []) + data.get("exclude", [])))

    files = list(_walk(folder_p, exclude, baseline_p))
    print(f"  Hashing {len(files)} file(s) with {threads} thread(s) [{algorithm.upper()}]…")

    current, skipped = _scan_all(files, algorithm, threads)

    # ── Compare ──
    changes: list[FileChange] = []

    for path, stored_dict in stored.items():
        stored_meta = FileMeta.from_dict(path, stored_dict)
        if path not in current:
            changes.append(FileChange(path, Status.MISSING))
        elif current[path].hash != stored_meta.hash:
            # Describe exactly what the OS-level metadata shows changed
            cur   = current[path]
            parts = []
            if cur.size != stored_meta.size:
                delta = cur.size - stored_meta.size
                parts.append(f"size {stored_meta.size}→{cur.size} ({delta:+,} bytes)")
            if cur.permissions != stored_meta.permissions:
                parts.append(f"perms {stored_meta.permissions}→{cur.permissions}")
            changes.append(FileChange(path, Status.MODIFIED,
                                      ", ".join(parts) if parts else "hash mismatch"))
        else:
            changes.append(FileChange(path, Status.OK))

    for path in current:
        if path not in stored:
            changes.append(FileChange(path, Status.NEW))

    return IntegrityReport(
        folder=str(folder_p),
        baseline_at=baseline_at,
        checked_at=datetime.now(timezone.utc).isoformat(),
        algorithm=algorithm,
        changes=changes,
        skipped=skipped,
    )

# ── Watch mode ────────────────────────────────────────────────────────

def watch(
    folder:        str,
    baseline_path: str       = DEFAULT_BASELINE,
    interval:      int       = DEFAULT_POLL_SECS,
    exclude:       list[str] | None = None,
    threads:       int       = DEFAULT_THREADS,
) -> None:
    """Poll folder on a fixed interval; print full report only on violations."""
    print(f"\n  👁  Watching '{folder}' every {interval}s  (Ctrl-C to stop)\n")
    check_num = 0
    try:
        while True:
            check_num += 1
            ts = datetime.now().strftime("%H:%M:%S")
            try:
                report = check_integrity(folder, baseline_path, exclude, threads)
                icon   = {"OK": "✅", "WARNING": "⚠️ ", "CRITICAL": "🔴"}[report.severity]
                print(f"  [{ts}] #{check_num:<4} {icon} {report.severity:<9}  "
                      f"modified={len(report.modified)}  "
                      f"missing={len(report.missing)}  "
                      f"new={len(report.new)}")
                if report.severity == "CRITICAL":
                    report.display()
            except Exception as exc:
                print(f"  [{ts}] ERROR: {exc}")
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n  Watch stopped after {check_num} check(s).")

# ── CLI ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="fim",
        description="File Integrity Monitor — detect unauthorised changes to files",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # fim create <folder>
    p_c = sub.add_parser("create", help="Create a new hash baseline")
    p_c.add_argument("folder")
    p_c.add_argument("-b", "--baseline",  default=DEFAULT_BASELINE)
    p_c.add_argument("-a", "--algorithm", default=DEFAULT_ALGORITHM, choices=SUPPORTED_ALGORITHMS)
    p_c.add_argument("-e", "--exclude",   nargs="*", default=[], metavar="GLOB",
                     help="Glob patterns to skip, e.g. '*.log' '.git/*'")
    p_c.add_argument("-t", "--threads",   type=int, default=DEFAULT_THREADS)

    # fim check <folder>
    p_k = sub.add_parser("check", help="Check integrity against the baseline")
    p_k.add_argument("folder")
    p_k.add_argument("-b", "--baseline", default=DEFAULT_BASELINE)
    p_k.add_argument("-e", "--exclude",  nargs="*", default=[], metavar="GLOB")
    p_k.add_argument("-t", "--threads",  type=int, default=DEFAULT_THREADS)
    p_k.add_argument("-o", "--output",   default=None, help="Save report as JSON")
    p_k.add_argument("--show-ok", action="store_true", help="Also list unchanged files")

    # fim watch <folder>
    p_w = sub.add_parser("watch", help="Continuously monitor for changes")
    p_w.add_argument("folder")
    p_w.add_argument("-b", "--baseline", default=DEFAULT_BASELINE)
    p_w.add_argument("-i", "--interval", type=int, default=DEFAULT_POLL_SECS)
    p_w.add_argument("-e", "--exclude",  nargs="*", default=[], metavar="GLOB")
    p_w.add_argument("-t", "--threads",  type=int, default=DEFAULT_THREADS)

    args = parser.parse_args()

    try:
        if args.command == "create":
            create_baseline(args.folder, args.baseline, args.algorithm,
                            args.exclude, args.threads)

        elif args.command == "check":
            report = check_integrity(args.folder, args.baseline,
                                     args.exclude, args.threads)
            report.display(show_ok=args.show_ok)
            if args.output:
                report.save(args.output)

        elif args.command == "watch":
            watch(args.folder, args.baseline, args.interval,
                  args.exclude, args.threads)

    except (FileNotFoundError, ValueError) as e:
        print(f"\n  Error: {e}")
