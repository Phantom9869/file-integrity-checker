from __future__ import annotations
# file_integrity_monitor.py
import hashlib
import json
import os
import stat
import tempfile
import time
import fnmatch
import argparse
import sys
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

# CLI exit codes: check uses 0/1/2 by severity; 3 is any operational error.
EXIT_OK       = 0
EXIT_WARNING  = 1
EXIT_CRITICAL = 2
EXIT_ERROR    = 3

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
        _atomic_write_text(Path(path), json.dumps(self.to_dict(), indent=2))
        print(f"  Report saved → '{path}'")

# ── I/O helpers ───────────────────────────────────────────────────────

def _validate_threads(threads: int) -> int:
    if not isinstance(threads, int) or isinstance(threads, bool) or threads < 1:
        raise ValueError(f"threads must be a positive integer, got {threads!r}")
    return threads

def _require_folder(folder: str) -> Path:
    folder_p = Path(folder).resolve()
    if not folder_p.exists():
        raise FileNotFoundError(f"Folder not found: '{folder_p}'")
    if not folder_p.is_dir():
        raise ValueError(f"Not a directory: '{folder_p}'")
    return folder_p

def _atomic_write_text(path: Path, text: str) -> None:
    """Write text to path via a temp file + replace so a crash cannot truncate it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".fim-", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

def _load_baseline(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Baseline at '{path}' is not valid JSON: {exc.msg}"
        ) from exc
    if not isinstance(data, dict) or not isinstance(data.get("files"), dict):
        raise ValueError(
            f"Baseline at '{path}' is missing the 'files' field. "
            "Recreate it with the 'create' command."
        )
    algorithm = data.get("algorithm", DEFAULT_ALGORITHM)
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm '{algorithm}' in baseline. "
            f"Use: {', '.join(sorted(SUPPORTED_ALGORITHMS))}"
        )
    return data

# ── Hashing ───────────────────────────────────────────────────────────

def _make_hasher(algorithm: str):
    return hashlib.blake2b() if algorithm == "blake2b" else hashlib.new(algorithm)

def hash_file(filepath: Path, algorithm: str = DEFAULT_ALGORITHM) -> str:
    if filepath.is_symlink():
        raise OSError(f"Refusing to hash symlink: {filepath}")
    h = _make_hasher(algorithm)
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()

def _get_meta(filepath: Path, relative: str, algorithm: str) -> FileMeta:
    """Hash the file, then lstat it so a swapped-in symlink is not followed."""
    digest = hash_file(filepath, algorithm)
    st = filepath.lstat()
    if stat.S_ISLNK(st.st_mode):
        raise OSError(f"Refusing to hash symlink: {filepath}")
    return FileMeta(
        path=relative,
        hash=digest,
        size=st.st_size,
        mtime=st.st_mtime,
        permissions=oct(stat.S_IMODE(st.st_mode)),
    )

# ── File walking ──────────────────────────────────────────────────────

def _contained_path(folder: Path, relative: str) -> Path | None:
    """Return folder/relative only if relative stays inside folder."""
    if not relative or os.path.isabs(relative):
        return None
    parts = Path(relative).parts
    if any(part in (os.pardir, "..") for part in parts):
        return None
    return folder / relative

def _is_excluded(relative: str, exclude: list[str]) -> bool:
    posix = relative.replace(os.sep, "/")
    return any(
        fnmatch.fnmatch(relative, pat) or fnmatch.fnmatch(posix, pat)
        for pat in exclude
    )

def _walk(folder: Path, exclude: list[str],
          baseline_path: Path) -> Iterator[tuple[Path, str]]:
    """Yield (abs_path, rel_path) for regular files; never follow symlinks."""
    try:
        baseline_resolved = baseline_path.resolve()
    except OSError:
        baseline_resolved = baseline_path

    for dirpath, dirnames, filenames in os.walk(folder, followlinks=False):
        # os.walk already skips directory symlinks; keep the filter as a belt.
        dirnames[:] = [
            name for name in sorted(dirnames)
            if not Path(dirpath, name).is_symlink()
        ]
        for name in sorted(filenames):
            filepath = Path(dirpath) / name
            if filepath.is_symlink():
                continue
            if not filepath.is_file():
                continue
            try:
                if filepath.resolve() == baseline_resolved:
                    continue
            except OSError:
                continue
            relative = str(filepath.relative_to(folder))
            if _is_excluded(relative, exclude):
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
        except OSError:
            # Permission denied, file vanished mid-scan, and similar I/O errors
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
        raise ValueError(f"Unsupported algorithm '{algorithm}'. Use: {', '.join(sorted(SUPPORTED_ALGORITHMS))}")

    folder_p   = _require_folder(folder)
    baseline_p = Path(baseline_path).resolve()
    threads    = _validate_threads(threads)
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
    _atomic_write_text(baseline_p, json.dumps(data, indent=2))

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

    data        = _load_baseline(baseline_p)
    algorithm   = data.get("algorithm", DEFAULT_ALGORITHM)
    baseline_at = data.get("created_at", "unknown")
    stored: dict[str, dict] = data["files"]

    folder_p = _require_folder(folder)
    threads  = _validate_threads(threads)
    exclude  = list(set((exclude or []) + data.get("exclude", [])))

    files = list(_walk(folder_p, exclude, baseline_p))
    print(f"  Hashing {len(files)} file(s) with {threads} thread(s) [{algorithm.upper()}]…")

    current, skipped = _scan_all(files, algorithm, threads)

    # ── Compare ──
    changes: list[FileChange] = []

    for path, stored_dict in stored.items():
        stored_meta = FileMeta.from_dict(path, stored_dict)
        if path not in current:
            on_disk = _contained_path(folder_p, path)
            if on_disk is not None and on_disk.is_symlink():
                changes.append(FileChange(
                    path, Status.MODIFIED, "replaced by a symlink"))
            else:
                changes.append(FileChange(path, Status.MISSING))
            continue

        cur = current[path]
        parts = []
        if cur.hash != stored_meta.hash:
            # Describe exactly what the OS-level metadata shows changed
            if cur.size != stored_meta.size:
                delta = cur.size - stored_meta.size
                parts.append(f"size {stored_meta.size}→{cur.size} ({delta:+,} bytes)")
            else:
                parts.append("hash mismatch")
        # Permission-only changes must be flagged too: the hash can stay the
        # same after chmod, which previously left the file marked OK.
        # "?" is the placeholder used when an older baseline omitted perms.
        if (
            stored_meta.permissions != "?"
            and cur.permissions != stored_meta.permissions
        ):
            parts.append(f"perms {stored_meta.permissions}→{cur.permissions}")
        if parts:
            changes.append(FileChange(path, Status.MODIFIED, ", ".join(parts)))
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
    if not isinstance(interval, int) or isinstance(interval, bool) or interval < 1:
        raise ValueError(f"interval must be a positive integer, got {interval!r}")
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

def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"must be a positive integer, got {value!r}"
        ) from None
    if parsed < 1:
        raise argparse.ArgumentTypeError(
            f"must be a positive integer, got {value!r}"
        )
    return parsed

class _ArgumentParser(argparse.ArgumentParser):
    """Use exit code 3 for usage errors so it is not confused with CRITICAL."""

    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(EXIT_ERROR, f"{self.prog}: error: {message}\n")

def build_parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
        prog="fim",
        description="File Integrity Monitor — detect unauthorised changes to files",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_c = sub.add_parser("create", help="Create a new hash baseline")
    p_c.add_argument("folder")
    p_c.add_argument("-b", "--baseline",  default=DEFAULT_BASELINE)
    p_c.add_argument("-a", "--algorithm", default=DEFAULT_ALGORITHM, choices=sorted(SUPPORTED_ALGORITHMS))
    p_c.add_argument("-e", "--exclude",   nargs="*", default=[], metavar="GLOB",
                     help="Glob patterns to skip, e.g. '*.log' '.git/*'")
    p_c.add_argument("-t", "--threads",   type=_positive_int, default=DEFAULT_THREADS)

    p_k = sub.add_parser("check", help="Check integrity against the baseline")
    p_k.add_argument("folder")
    p_k.add_argument("-b", "--baseline", default=DEFAULT_BASELINE)
    p_k.add_argument("-e", "--exclude",  nargs="*", default=[], metavar="GLOB")
    p_k.add_argument("-t", "--threads",  type=_positive_int, default=DEFAULT_THREADS)
    p_k.add_argument("-o", "--output",   default=None, help="Save report as JSON")
    p_k.add_argument("--show-ok", action="store_true", help="Also list unchanged files")

    p_w = sub.add_parser("watch", help="Continuously monitor for changes")
    p_w.add_argument("folder")
    p_w.add_argument("-b", "--baseline", default=DEFAULT_BASELINE)
    p_w.add_argument("-i", "--interval", type=_positive_int, default=DEFAULT_POLL_SECS)
    p_w.add_argument("-e", "--exclude",  nargs="*", default=[], metavar="GLOB")
    p_w.add_argument("-t", "--threads",  type=_positive_int, default=DEFAULT_THREADS)
    return parser

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "create":
            create_baseline(args.folder, args.baseline, args.algorithm,
                            args.exclude, args.threads)
            return EXIT_OK

        if args.command == "check":
            report = check_integrity(args.folder, args.baseline,
                                     args.exclude, args.threads)
            report.display(show_ok=args.show_ok)
            if args.output:
                report.save(args.output)
            return {
                "OK": EXIT_OK,
                "WARNING": EXIT_WARNING,
                "CRITICAL": EXIT_CRITICAL,
            }[report.severity]

        watch(args.folder, args.baseline, args.interval,
              args.exclude, args.threads)
        return EXIT_OK

    except (FileNotFoundError, ValueError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130

if __name__ == "__main__":
    sys.exit(main())
