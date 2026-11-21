# File Integrity Checker

A Python CLI that detects unauthorized changes to files in a folder. It
builds a baseline of cryptographic hashes (SHA-256 by default, or SHA-512
or BLAKE2b) plus size and permission metadata, then compares the folder
against that baseline.

## Requirements

Python 3.9 or newer. There are no third-party runtime dependencies.

```bash
python3 -m pip install -e .
```

That installs the `fim` command. You can also run the script directly:

```bash
python3 file_integrity.py <command> ...
```

## Usage

Create a baseline, then check the same folder later:

```bash
fim create ./watched --baseline baseline.json
fim check  ./watched --baseline baseline.json
```

`check` prints a report and exits with a status you can use in scripts:

| Exit code | Meaning                                      |
|-----------|----------------------------------------------|
| 0         | No changes                                   |
| 1         | New files only (WARNING)                     |
| 2         | Modified or missing files (CRITICAL)         |
| 3         | Usage error, missing folder, or bad baseline |

Continuous monitoring:

```bash
fim watch ./watched --baseline baseline.json --interval 30
```

Useful options (all commands accept `--baseline` / `-b` and `--exclude`):

- `-a, --algorithm` — `sha256` (default), `sha512`, or `blake2b` (create only)
- `-e, --exclude` — glob patterns to skip, for example `*.log` `.git/*`
- `-t, --threads` — concurrent hashers (default: 8)
- `-o, --output` — write the check report as JSON
- `--show-ok` — also list unchanged files in the check report
- `-i, --interval` — seconds between watch polls (default: 30)

## What it flags

- **MODIFIED** — content hash changed, or permissions changed (for example `chmod`), or a tracked regular file was replaced by a symlink
- **MISSING** — a file in the baseline is gone
- **NEW** — a regular file appeared that is not in the baseline

Symlinks are not followed or hashed, so a link cannot pull files from
outside the watched folder into the baseline. The baseline is written
atomically so a crash mid-write cannot leave a truncated file.

## Tests

```bash
python3 -m pip install pytest
python3 -m pytest -q
```

CI runs the suite on Python 3.9, 3.11 and 3.13.
