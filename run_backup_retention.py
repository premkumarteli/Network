import argparse
import json

from dotenv import load_dotenv

from app.services.system_service import SystemService


def run_backup_retention(retention_days: int | None = None, dry_run: bool = False) -> dict:
    load_dotenv()
    service = SystemService()
    return service.cleanup_old_backups(retention_days=retention_days, dry_run=dry_run)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetVisor backup retention job")
    parser.add_argument(
        "--retention-days",
        type=int,
        default=None,
        help="Override the configured backup retention window in days.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report expired backups without deleting them.",
    )
    args = parser.parse_args()
    result = run_backup_retention(retention_days=args.retention_days, dry_run=args.dry_run)
    print(json.dumps(result, indent=2, sort_keys=True))
