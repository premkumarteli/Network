from __future__ import annotations

import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
BUILDER = PROJECT_ROOT / "scripts" / "build_deploy_bundles.py"


def main() -> int:
    print("[*] build_share_agent.py is deprecated; building the canonical agent bundle under build/deploy/")
    result = subprocess.run(
        [sys.executable, str(BUILDER), "--role", "agent"],
        cwd=PROJECT_ROOT,
        check=False,
    )
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
