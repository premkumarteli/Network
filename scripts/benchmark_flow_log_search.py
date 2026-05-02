from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.core.config import settings
from app.db.session import get_db_connection
from app.services.flow_service import flow_service


def benchmark_cases(*, ip_search: str, app_search: str, domain_search: str) -> tuple:
    return (
        ("recent", {}),
        ("ip_exact", {"search": ip_search}),
        ("app_prefix", {"search": app_search}),
        ("domain_prefix", {"search": domain_search}),
    )


def _execute_timed(cursor, sql: str, params: list | tuple) -> tuple[float, list[dict]]:
    started_at = time.perf_counter()
    cursor.execute(sql, tuple(params))
    rows = cursor.fetchall() or []
    return (time.perf_counter() - started_at) * 1000, rows


def _case_queries(organization_id: str, filters: dict, *, limit: int, offset: int) -> tuple[str, list, str, list]:
    where_sql, params = flow_service.build_flow_log_query_parts(organization_id, **filters)
    count_sql = f"SELECT COUNT(*) AS total FROM flow_logs WHERE {where_sql}"
    page_sql = f"""
        SELECT *
        FROM flow_logs
        WHERE {where_sql}
        ORDER BY last_seen DESC
        LIMIT %s OFFSET %s
    """
    return count_sql, list(params), page_sql, [*params, limit, offset]


def _benchmark_case(cursor, organization_id: str, name: str, filters: dict, *, limit: int, offset: int, runs: int) -> dict:
    count_sql, count_params, page_sql, page_params = _case_queries(
        organization_id,
        filters,
        limit=limit,
        offset=offset,
    )
    explain_sql = f"EXPLAIN {page_sql}"
    _, explain_rows = _execute_timed(cursor, explain_sql, page_params)

    count_times: list[float] = []
    page_times: list[float] = []
    total = 0
    row_count = 0
    for _ in range(runs):
        elapsed_ms, count_rows = _execute_timed(cursor, count_sql, count_params)
        count_times.append(elapsed_ms)
        total = int((count_rows[0] or {}).get("total") or 0) if count_rows else 0

        elapsed_ms, page_rows = _execute_timed(cursor, page_sql, page_params)
        page_times.append(elapsed_ms)
        row_count = len(page_rows)

    return {
        "name": name,
        "filters": filters,
        "total": total,
        "rows": row_count,
        "count_ms_avg": round(statistics.fmean(count_times), 3),
        "count_ms_p95": round(max(count_times), 3) if len(count_times) < 20 else round(statistics.quantiles(count_times, n=20)[18], 3),
        "page_ms_avg": round(statistics.fmean(page_times), 3),
        "page_ms_p95": round(max(page_times), 3) if len(page_times) < 20 else round(statistics.quantiles(page_times, n=20)[18], 3),
        "explain": explain_rows,
    }


def run_benchmark(*, organization_id: str, limit: int, offset: int, runs: int, cases: tuple) -> dict:
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        results = [
            _benchmark_case(cursor, organization_id, name, filters, limit=limit, offset=offset, runs=runs)
            for name, filters in cases
        ]
        return {
            "organization_id": organization_id,
            "limit": limit,
            "offset": offset,
            "runs": runs,
            "cases": results,
        }
    finally:
        cursor.close()
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark NetVisor flow log search queries.")
    parser.add_argument("--organization-id", default=settings.DEFAULT_ORGANIZATION_ID or "default-org-id")
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--ip-search", default="10.159.79.96")
    parser.add_argument("--app-search", default="Micro")
    parser.add_argument("--domain-search", default="edge.microsoft.com")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    args = parser.parse_args()

    report = run_benchmark(
        organization_id=args.organization_id,
        limit=max(args.limit, 1),
        offset=max(args.offset, 0),
        runs=max(args.runs, 1),
        cases=benchmark_cases(
            ip_search=args.ip_search,
            app_search=args.app_search,
            domain_search=args.domain_search,
        ),
    )
    if args.json:
        print(json.dumps(report, indent=2, default=str))
        return 0

    print(f"Flow log search benchmark for organization={report['organization_id']}")
    print(f"limit={report['limit']} offset={report['offset']} runs={report['runs']}")
    for case in report["cases"]:
        explain_indexes = sorted({str(row.get("key") or "-") for row in case["explain"]})
        print(
            f"- {case['name']}: total={case['total']} rows={case['rows']} "
            f"count_avg={case['count_ms_avg']}ms page_avg={case['page_ms_avg']}ms "
            f"indexes={', '.join(explain_indexes)}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
