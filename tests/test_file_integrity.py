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


def test_hash_file_does_not_follow_a_symlink_even_if_the_name_check_misses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The open itself must refuse to follow, not just the is_symlink() pre-check."""
    real = _write(tmp_path / "real.txt", "secret-target")
    link = tmp_path / "link.txt"
    link.symlink_to(real)
    monkeypatch.setattr(Path, "is_symlink", lambda self: False)
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


def test_create_rejects_missing_folder(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="Folder not found"):
        _create(tmp_path / "nope", tmp_path / "baseline.json")


def test_create_rejects_file_as_folder(tmp_path: Path) -> None:
    not_a_dir = _write(tmp_path / "file.txt")
    with pytest.raises(ValueError, match="Not a directory"):
        _create(not_a_dir, tmp_path / "baseline.json")


def test_check_rejects_missing_folder(tmp_path: Path) -> None:
    folder = tmp_path / "watched"
    _write(folder / "a.txt")
    baseline = tmp_path / "baseline.json"
    _create(folder, baseline)
    missing = tmp_path / "gone"
    with pytest.raises(FileNotFoundError, match="Folder not found"):
        _check(missing, baseline)


def test_corrupt_baseline_raises_value_error(tmp_path: Path) -> None:
    folder = tmp_path / "watched"
    folder.mkdir()
    baseline = tmp_path / "baseline.json"
    baseline.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid JSON"):
        _check(folder, baseline)


def test_legacy_baseline_without_files_field_is_rejected(tmp_path: Path) -> None:
    folder = tmp_path / "watched"
    folder.mkdir()
    baseline = tmp_path / "baseline.json"
    # The old repo baseline was a flat path-to-hash map with no "files" key.
    baseline.write_text(
        '{"file_integrity.py": "1c77fea67a454a54ca96f3a3b7138f5cf6dfb615ca8ed5e4266a836cfcc12f4a"}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="missing the 'files' field"):
        _check(folder, baseline)


def test_baseline_with_unknown_algorithm_is_rejected(tmp_path: Path) -> None:
    folder = tmp_path / "watched"
    folder.mkdir()
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        '{"algorithm": "md5", "files": {"a.txt": {"hash": "abc"}}}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Unsupported algorithm 'md5'"):
        _check(folder, baseline)


@pytest.mark.parametrize("threads", [0, -1, True])
def test_invalid_thread_count_is_rejected(tmp_path: Path, threads: int) -> None:
    folder = tmp_path / "watched"
    _write(folder / "a.txt")
    with pytest.raises(ValueError, match="threads must be a positive integer"):
        fim.create_baseline(str(folder), str(tmp_path / "baseline.json"), threads=threads)


def test_file_that_vanishes_during_scan_is_skipped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    folder = tmp_path / "watched"
    _write(folder / "stay.txt")
    _write(folder / "gone.txt")
    baseline = tmp_path / "baseline.json"

    real_meta = fim._get_meta

    def flaky(filepath, relative, algorithm):
        if relative == "gone.txt":
            raise FileNotFoundError("vanished")
        return real_meta(filepath, relative, algorithm)

    monkeypatch.setattr(fim, "_get_meta", flaky)
    _create(folder, baseline)

    import json

    data = json.loads(baseline.read_text(encoding="utf-8"))
    assert "stay.txt" in data["files"]
    assert "gone.txt" not in data["files"]


def test_atomic_write_replaces_file_and_leaves_no_temp(tmp_path: Path) -> None:
    path = tmp_path / "out.json"
    path.write_text("stale", encoding="utf-8")
    fim._atomic_write_text(path, '{"ok": true}')
    assert path.read_text(encoding="utf-8") == '{"ok": true}'
    leftovers = list(tmp_path.glob(".fim-*.tmp"))
    assert leftovers == []


def test_main_create_and_check_ok(tmp_path: Path) -> None:
    folder = tmp_path / "watched"
    _write(folder / "a.txt")
    baseline = tmp_path / "baseline.json"
    assert fim.main(["create", str(folder), "-b", str(baseline), "-t", "1"]) == fim.EXIT_OK
    assert fim.main(["check", str(folder), "-b", str(baseline), "-t", "1"]) == fim.EXIT_OK


def test_main_check_warning_and_critical(tmp_path: Path) -> None:
    folder = tmp_path / "watched"
    _write(folder / "a.txt")
    baseline = tmp_path / "baseline.json"
    assert fim.main(["create", str(folder), "-b", str(baseline), "-t", "1"]) == 0

    _write(folder / "b.txt", "new")
    assert fim.main(["check", str(folder), "-b", str(baseline), "-t", "1"]) == fim.EXIT_WARNING

    (folder / "a.txt").write_text("edited", encoding="utf-8")
    assert fim.main(["check", str(folder), "-b", str(baseline), "-t", "1"]) == fim.EXIT_CRITICAL


def test_main_missing_baseline_prints_error_and_exits_3(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    folder = tmp_path / "watched"
    folder.mkdir()
    code = fim.main(["check", str(folder), "-b", str(tmp_path / "missing.json")])
    captured = capsys.readouterr()
    assert code == fim.EXIT_ERROR
    assert "Error:" in captured.err
    assert "No baseline" in captured.err
    assert captured.err.endswith("\n")


def test_main_rejects_non_positive_threads(tmp_path: Path) -> None:
    folder = tmp_path / "watched"
    folder.mkdir()
    with pytest.raises(SystemExit) as exc:
        fim.main(["create", str(folder), "-t", "0"])
    assert exc.value.code == fim.EXIT_ERROR


def test_main_rejects_non_positive_interval(tmp_path: Path) -> None:
    folder = tmp_path / "watched"
    folder.mkdir()
    with pytest.raises(SystemExit) as exc:
        fim.main(["watch", str(folder), "-i", "-5"])
    assert exc.value.code == fim.EXIT_ERROR


def test_watch_rejects_invalid_interval(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="interval must be a positive integer"):
        fim.watch(str(tmp_path), str(tmp_path / "b.json"), interval=0)


def test_main_saves_json_report(tmp_path: Path) -> None:
    folder = tmp_path / "watched"
    _write(folder / "a.txt")
    baseline = tmp_path / "baseline.json"
    out = tmp_path / "report.json"
    fim.main(["create", str(folder), "-b", str(baseline), "-t", "1"])
    (folder / "a.txt").write_text("edited", encoding="utf-8")
    code = fim.main([
        "check", str(folder), "-b", str(baseline), "-t", "1", "-o", str(out),
    ])
    assert code == fim.EXIT_CRITICAL
    assert out.is_file()
    import json
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["severity"] == "CRITICAL"

def test_check_time_exclude_does_not_mark_baseline_files_missing(tmp_path: Path) -> None:
    folder = tmp_path / "watched"
    _write(folder / "keep.txt")
    _write(folder / "noise.log", "log")
    baseline = tmp_path / "baseline.json"
    _create(folder, baseline)

    report = _check(folder, baseline, exclude=["*.log"])

    assert report.severity == "OK"
    assert {c.path for c in report.ok} == {"keep.txt"}
    assert report.missing == []
    assert all(not c.path.endswith(".log") for c in report.changes)


def test_readme_documents_the_cli() -> None:

    readme = Path(__file__).resolve().parents[1] / "README.md"
    text = readme.read_text(encoding="utf-8")
    assert "fim create" in text
    assert "fim check" in text
    assert "fim watch" in text
    assert "Choose option 1" not in text
    for code, label in (("0", "No changes"), ("1", "WARNING"), ("2", "CRITICAL"), ("3", "Usage error")):
        assert code in text and label.split()[0] in text


def test_pyproject_exposes_fim_entry_point() -> None:
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")
    assert "fim = \"file_integrity:main\"" in text
    assert callable(fim.main)
