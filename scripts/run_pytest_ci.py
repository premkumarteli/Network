from __future__ import annotations

import os
import re
import subprocess
import sys


def _escape_annotation(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _failure_summary(output: str) -> str:
    lines = output.splitlines()
    interesting: list[str] = []
    capture = False

    for line in lines:
        if line.startswith(("FAILED ", "ERROR ")) or re.match(r"^E\s+", line):
            capture = True
        if capture:
            interesting.append(line)
        if capture and len(interesting) >= 18:
            break

    if not interesting:
        interesting = lines[-40:]

    summary = "\n".join(interesting).strip()
    return summary or "pytest failed without producing output"


def main() -> int:
    args = sys.argv[1:] or ["-q"]
    command = [sys.executable, "-m", "pytest", *args]
    result = subprocess.run(command, text=True, capture_output=True)

    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)

    if result.returncode and os.getenv("GITHUB_ACTIONS"):
        summary = _failure_summary(result.stdout + "\n" + result.stderr)
        print(f"::error title=Backend pytest failure::{_escape_annotation(summary)}")

    return int(result.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
