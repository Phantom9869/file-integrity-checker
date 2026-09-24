import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, field

BASELINE_FILE = "baseline.json"

# --- Hashing ---

def hash_file(filepath: Path) -> str:
    """SHA-256 hash a file, reading in 64 KB chunks."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):  # 64 KB > 4 KB = faster I/O
            sha256.update(chunk)
    return sha256.hexdigest()

# --- Baseline ---

def create_baseline(folder: Path, baseline_path: Path = Path(BASELINE_FILE)) -> None:
    """Walk folder recursively and save a hash baseline to JSON."""
    folder = Path(folder).resolve()
    baseline_path = Path(baseline_path).resolve()

    hashes: dict[str, str] = {}
    for filepath in folder.rglob("*"):                          # recursive — original missed subdirs
        if filepath.is_file() and filepath != baseline_path:   # skip the baseline file itself
            relative = str(filepath.relative_to(folder))
            try:
                hashes[relative] = hash_file(filepath)
            except PermissionError:
                print(f"  [SKIP] Permission denied: {relative}")

    data = {
        "folder": str(folder),
        "created_at": datetime.now(timezone.utc).isoformat(),  # log when baseline was made
        "files": hashes,
    }
    with open(baseline_path, "w") as f:
        json.dump(data, f, indent=4)
    print(f"Baseline created: {len(hashes)} file(s) → {baseline_path}")

# --- Report ---

@dataclass
class IntegrityReport:
    ok:       list[str] = field(default_factory=list)
    modified: list[str] = field(default_factory=list)
    missing:  list[str] = field(default_factory=list)
    new:      list[str] = field(default_factory=list)   # original never detected new files

    def print(self) -> None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n--- Integrity Check ({timestamp}) ---")
        for name in self.ok:       print(f"  [OK]       {name}")
        for name in self.modified: print(f"  [MODIFIED] {name}")
        for name in self.missing:  print(f"  [MISSING]  {name}")
        for name in self.new:      print(f"  [NEW]      {name}")
        print(f"\nSummary: {len(self.ok)} ok | {len(self.modified)} modified | "
              f"{len(self.missing)} missing | {len(self.new)} new")
        if self.modified or self.missing:
            print("⚠️  WARNING: Integrity violations detected!")

# --- Check ---

def check_integrity(folder: Path, baseline_path: Path = Path(BASELINE_FILE)) -> IntegrityReport:
    """Compare current folder state against the stored baseline."""
    folder = Path(folder).resolve()
    baseline_path = Path(baseline_path).resolve()

    if not baseline_path.exists():
        raise FileNotFoundError(f"No baseline found at '{baseline_path}'. Run option 1 first.")

    with open(baseline_path) as f:
        data = json.load(f)

    print(f"Baseline created at: {data.get('created_at', 'unknown')}")
    baseline: dict[str, str] = data["files"]

    # Hash every current file in the folder
    current: dict[str, str] = {}
    for filepath in folder.rglob("*"):
        if filepath.is_file() and filepath != baseline_path:
            relative = str(filepath.relative_to(folder))
            try:
                current[relative] = hash_file(filepath)
            except PermissionError:
                print(f"  [SKIP] Permission denied: {relative}")

    report = IntegrityReport()

    for name, original_hash in baseline.items():
        if name not in current:
            report.missing.append(name)
        elif current[name] == original_hash:
            report.ok.append(name)
        else:
            report.modified.append(name)

    for name in current:
        if name not in baseline:
            report.new.append(name)   # files that didn't exist at baseline time

    return report

# --- Entry point ---

if __name__ == "__main__":
    print("File Integrity Monitor")
    print("  1. Create baseline")
    print("  2. Check integrity")
    choice = input("\nChoose (1/2): ").strip()
    folder = input("Folder to monitor: ").strip()
    baseline = input(f"Baseline path (Enter = '{BASELINE_FILE}'): ").strip() or BASELINE_FILE

    try:
        if choice == "1":
            create_baseline(folder, baseline)
        elif choice == "2":
            report = check_integrity(folder, baseline)
            report.print()
        else:
            print("Invalid choice — enter 1 or 2.")
    except (FileNotFoundError, PermissionError) as e:
        print(f"Error: {e}")
