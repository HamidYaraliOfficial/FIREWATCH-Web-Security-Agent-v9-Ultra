"""Report downloads must never trust arbitrary paths stored in the database."""
from pathlib import Path
from types import SimpleNamespace

import pytest

import app.main as main


def test_ultra_safe_report_path_accepts_file_under_scan_directory(tmp_path, monkeypatch):
    scan_id = "e9fc91e7-a038-4d03-a328-4deebc5d3c5e"
    monkeypatch.setattr(main, "settings", SimpleNamespace(report_dir=str(tmp_path / "reports")))
    file_path = tmp_path / "reports" / scan_id / "report.html"
    file_path.parent.mkdir(parents=True)
    file_path.write_text("safe", encoding="utf-8")
    assert main._safe_report_path(scan_id, str(file_path)) == file_path.resolve()


def test_ultra_safe_report_path_rejects_path_traversal(tmp_path, monkeypatch):
    scan_id = "e9fc91e7-a038-4d03-a328-4deebc5d3c5e"
    report_root = tmp_path / "reports"
    monkeypatch.setattr(main, "settings", SimpleNamespace(report_dir=str(report_root)))
    outside = tmp_path / "secret.txt"
    outside.write_text("must not leak", encoding="utf-8")
    assert main._safe_report_path(scan_id, str(outside)) is None
    assert main._safe_report_path(scan_id, str(report_root / scan_id / ".." / ".." / "secret.txt")) is None


def test_ultra_safe_report_path_rejects_missing_file_and_symlink(tmp_path, monkeypatch):
    scan_id = "e9fc91e7-a038-4d03-a328-4deebc5d3c5e"
    report_root = tmp_path / "reports"
    monkeypatch.setattr(main, "settings", SimpleNamespace(report_dir=str(report_root)))
    folder = report_root / scan_id
    folder.mkdir(parents=True)
    assert main._safe_report_path(scan_id, str(folder / "missing.html")) is None
    outside = tmp_path / "outside.html"
    outside.write_text("outside", encoding="utf-8")
    link = folder / "link.html"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable on this platform")
    assert main._safe_report_path(scan_id, str(link)) is None
