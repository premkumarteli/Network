from __future__ import annotations

import os
import shutil
import tempfile
import uuid
from pathlib import Path

import pytest

_WORKSPACE_TMP_ROOT: Path | None = None


def _configure_pytest_tempdir() -> None:
    # Keep pytest temporary directories inside the workspace so Windows temp ACLs
    # or stale numbered-dir cleanup do not break tmp_path-based tests.
    global _WORKSPACE_TMP_ROOT
    workspace_tmp = Path(__file__).resolve().parent / ".pytest_tmp" / f"run-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    workspace_tmp.mkdir(parents=True, exist_ok=True)
    _WORKSPACE_TMP_ROOT = workspace_tmp
    for key in ("TMP", "TEMP", "TMPDIR"):
        os.environ[key] = str(workspace_tmp)
    tempfile.tempdir = str(workspace_tmp)


_configure_pytest_tempdir()


@pytest.fixture
def tmp_path():
    # Avoid pytest's own numbered temp factory on this machine; it hits ACL issues
    # in the default temp roots. A plain workspace-local path is enough for these tests.
    root = Path(__file__).resolve().parent / ".pytest_tmp" / f"manual-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    root.mkdir(parents=True, exist_ok=False)
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def pytest_sessionfinish(session, exitstatus):
    workspace_root = Path(__file__).resolve().parent
    for path in workspace_root.glob(".pytest_tmp*"):
        shutil.rmtree(path, ignore_errors=True)
    if _WORKSPACE_TMP_ROOT is not None:
        shutil.rmtree(_WORKSPACE_TMP_ROOT, ignore_errors=True)
