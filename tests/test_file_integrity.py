"""Tests for the file integrity checker."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

import file_integrity as fim


def _write(path: Path, content: str = "hello") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _create(folder: Path, baseline: Path, **kwargs) -> None:
    fim.create_baseline(str(folder), str(baseline), threads=1, **kwargs)


def _check(folder: Path, baseline: Path, **kwargs):
    return fim.check_integrity(str(folder), str(baseline), threads=1, **kwargs)


def test_unchanged_files_are_ok(tmp_path: Path) -> None:
    folder = tmp_path / "watched"
    _write(folder / "a.txt")
    _write(folder / "sub" / "b.txt", "nested")
    baseline = tmp_path / "baseline.json"
    _create(folder, baseline)

    report = _check(folder, baseline)

    assert report.severity == "OK"
    assert {c.path for c in report.ok} == {"a.txt", os.path.join("sub", "b.txt")}
    assert report.modified == []
    assert report.missing == []
    assert report.new == []


def test_content_change_is_modified(tmp_path: Path) -> None:
    folder = tmp_path / "watched"
    target = _write(folder / "a.txt", "original")
    baseline = tmp_path / "baseline.json"
    _create(folder, baseline)

    target.write_text("changed", encoding="utf-8")
    report = _check(folder, baseline)

    assert report.severity == "CRITICAL"
    assert len(report.modified) == 1
    change = report.modified[0]
    assert change.path == "a.txt"
    assert "size" in change.detail


def test_same_size_content_change_is_hash_mismatch(tmp_path: Path) -> None:
    folder = tmp_path / "watched"
    target = _write(folder / "a.txt", "aaaa")
    baseline = tmp_path / "baseline.json"
    _create(folder, baseline)

    target.write_text("bbbb", encoding="utf-8")
    report = _check(folder, baseline)

    assert report.severity == "CRITICAL"
    assert report.modified[0].detail == "hash mismatch"


def test_missing_file_is_critical(tmp_path: Path) -> None:
    folder = tmp_path / "watched"
    target = _write(folder / "a.txt")
    baseline = tmp_path / "baseline.json"
    _create(folder, baseline)

    target.unlink()
    report = _check(folder, baseline)

    assert report.severity == "CRITICAL"
    assert [c.path for c in report.missing] == ["a.txt"]


def test_new_file_is_warning(tmp_path: Path) -> None:
    folder = tmp_path / "watched"
    _write(folder / "a.txt")
    baseline = tmp_path / "baseline.json"
    _create(folder, baseline)

    _write(folder / "b.txt", "new")
    report = _check(folder, baseline)

    assert report.severity == "WARNING"
    assert [c.path for c in report.new] == ["b.txt"]


def test_permission_only_change_is_modified(tmp_path: Path) -> None:
    folder = tmp_path / "watched"
    target = _write(folder / "script.sh", "#!/bin/sh\necho hi\n")
    target.chmod(0o644)
    baseline = tmp_path / "baseline.json"
    _create(folder, baseline)

    target.chmod(0o755)
    report = _check(folder, baseline)

    assert report.severity == "CRITICAL"
    assert len(report.modified) == 1
    change = report.modified[0]
    assert change.path == "script.sh"
    assert "perms" in change.detail
    assert "0o644" in change.detail
    assert "0o755" in change.detail
    # Content did not change, so this must not be reported as a hash issue.
    assert "hash mismatch" not in change.detail
    assert "size" not in change.detail


def test_legacy_baseline_without_permissions_is_not_false_positive(tmp_path: Path) -> None:
    folder = tmp_path / "watched"
    target = _write(folder / "a.txt")
    digest = fim.hash_file(target)
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        '{"algorithm": "sha256", "created_at": "unknown", "files": '
        f'{{"a.txt": {{"hash": "{digest}"}}}}}}',
        encoding="utf-8",
    )

    report = _check(folder, baseline)

    assert report.severity == "OK"
    assert report.modified == []


@pytest.mark.parametrize("algorithm", sorted(fim.SUPPORTED_ALGORITHMS))
def test_supported_algorithms_round_trip(tmp_path: Path, algorithm: str) -> None:
    folder = tmp_path / "watched"
    _write(folder / "a.txt", "payload")
    baseline = tmp_path / "baseline.json"
    _create(folder, baseline, algorithm=algorithm)

    report = _check(folder, baseline)

    assert report.algorithm == algorithm
    assert report.severity == "OK"


def test_unsupported_algorithm_is_rejected(tmp_path: Path) -> None:
    folder = tmp_path / "watched"
    folder.mkdir()
    with pytest.raises(ValueError, match="Unsupported algorithm"):
        _create(folder, tmp_path / "baseline.json", algorithm="md5")


def test_exclude_patterns_are_honoured(tmp_path: Path) -> None:
    folder = tmp_path / "watched"
    _write(folder / "keep.txt")
    _write(folder / "noise.log", "ignore me")
    baseline = tmp_path / "baseline.json"
    _create(folder, baseline, exclude=["*.log"])

    _write(folder / "noise.log", "changed")
    _write(folder / "other.log", "also ignored")
    report = _check(folder, baseline, exclude=["*.log"])

    assert report.severity == "OK"
    assert all(not c.path.endswith(".log") for c in report.changes)


def test_baseline_inside_folder_is_not_inventoried(tmp_path: Path) -> None:
    folder = tmp_path / "watched"
    _write(folder / "a.txt")
    baseline = folder / "baseline.json"
    _create(folder, baseline)

    report = _check(folder, baseline)

    assert "baseline.json" not in {c.path for c in report.changes}
    assert report.severity == "OK"


def test_missing_baseline_raises(tmp_path: Path) -> None:
    folder = tmp_path / "watched"
    folder.mkdir()
    with pytest.raises(FileNotFoundError, match="No baseline"):
        _check(folder, tmp_path / "missing.json")


def test_report_save_omits_ok_entries(tmp_path: Path) -> None:
    folder = tmp_path / "watched"
    _write(folder / "a.txt")
    _write(folder / "b.txt", "keep")
    baseline = tmp_path / "baseline.json"
    _create(folder, baseline)
    (folder / "a.txt").write_text("edited", encoding="utf-8")

    report = _check(folder, baseline)
    out = tmp_path / "report.json"
    report.save(str(out))

    import json

    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["severity"] == "CRITICAL"
    statuses = {c["path"]: c["status"] for c in data["changes"]}
    assert statuses == {"a.txt": "MODIFIED"}
    assert "b.txt" not in statuses


def test_symlink_to_file_is_not_inventoried(tmp_path: Path) -> None:
    folder = tmp_path / "watched"
    _write(folder / "real.txt", "inside")
    outside = _write(tmp_path / "outside.txt", "secret")
    (folder / "link.txt").symlink_to(outside)
    baseline = tmp_path / "baseline.json"
    _create(folder, baseline)

    report = _check(folder, baseline)

    assert report.severity == "OK"
    assert {c.path for c in report.ok} == {"real.txt"}
    assert "link.txt" not in {c.path for c in report.changes}


def test_directory_symlink_is_not_followed(tmp_path: Path) -> None:
    folder = tmp_path / "watched"
    _write(folder / "real.txt")
    outside_dir = tmp_path / "elsewhere"
    _write(outside_dir / "secret.txt", "do not hash")
    (folder / "escape").symlink_to(outside_dir)
    baseline = tmp_path / "baseline.json"
    _create(folder, baseline)

    report = _check(folder, baseline)

    assert report.severity == "OK"
    assert {c.path for c in report.ok} == {"real.txt"}
    assert all("secret.txt" not in c.path for c in report.changes)
    assert all("escape" not in c.path for c in report.changes)


def test_tracked_file_replaced_by_symlink_is_modified(tmp_path: Path) -> None:
    folder = tmp_path / "watched"
    target = _write(folder / "a.txt", "original")
    decoy = _write(tmp_path / "decoy.txt", "original")
    baseline = tmp_path / "baseline.json"
    _create(folder, baseline)

    target.unlink()
    target.symlink_to(decoy)
    report = _check(folder, baseline)

    assert report.severity == "CRITICAL"
    assert len(report.modified) == 1
    assert report.modified[0].path == "a.txt"
    assert report.modified[0].detail == "replaced by a symlink"
    assert report.missing == []


def test_hash_file_refuses_symlink(tmp_path: Path) -> None:
    real = _write(tmp_path / "real.txt", "data")
    link = tmp_path / "link.txt"
    link.symlink_to(real)
    with pytest.raises(OSError, match="Refusing to hash symlink"):
        fim.hash_file(link)


def test_new_symlink_is_not_reported_as_new_file(tmp_path: Path) -> None:
    folder = tmp_path / "watched"
    _write(folder / "a.txt")
    baseline = tmp_path / "baseline.json"
    _create(folder, baseline)

    (folder / "link.txt").symlink_to(folder / "a.txt")
    report = _check(folder, baseline)

    assert report.severity == "OK"
    assert report.new == []
