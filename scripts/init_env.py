from __future__ import annotations

import argparse
import shutil
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_PATH = PROJECT_ROOT / ".env.example"
DEFAULT_TARGET_PATH = PROJECT_ROOT / ".env"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a local .env from the tracked NetVisor template."
    )
    parser.add_argument(
        "--template",
        type=Path,
        default=TEMPLATE_PATH,
        help=f"Template path to copy from (default: {TEMPLATE_PATH})",
    )
    parser.add_argument(
        "--target",
        type=Path,
        default=DEFAULT_TARGET_PATH,
        help=f"Target .env path to write (default: {DEFAULT_TARGET_PATH})",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite the target .env if it already exists.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    template_path = args.template.resolve()
    target_path = args.target.resolve()

    if not template_path.exists():
        raise FileNotFoundError(f"Template not found: {template_path}")

    if target_path.exists() and not args.force:
        print(f"[*] {target_path} already exists. Use --force to overwrite it.")
        return 0

    target_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(template_path, target_path)
    print(f"[+] Created {target_path} from {template_path}")
    print("[*] Edit the local .env before starting NetVisor services.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
