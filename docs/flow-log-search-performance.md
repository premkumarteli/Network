# Flow Log Search Performance

NetVisor flow-log search is intentionally split into a few predictable query shapes. The goal is to keep normal operations index-friendly while leaving deeper full-text search as a measured future decision.

## Search Semantics

- Empty search returns the newest rows for the organization ordered by `last_seen`.
- IP search uses exact equality across `src_ip`, `dst_ip`, `internal_device_ip`, and `external_endpoint_ip`.
- Host search uses exact `domain` / `sni` checks plus left-prefix host matches.
- Application search uses exact and left-prefix application matches.
- Broad contains search is not the default path because `%term%` patterns do not use normal B-tree indexes well on large MySQL tables.

## Supporting Indexes

Fresh installs include these flow-log indexes:

- `idx_flow_logs_org_last_seen`
- `idx_flow_logs_dst`
- `idx_flow_logs_internal_last_seen`
- `idx_flow_logs_org_app_last_seen`
- `idx_flow_logs_app_src_last_seen`
- `idx_flow_logs_domain_last_seen`
- `idx_flow_logs_sni_last_seen`
- `idx_flow_logs_session_id`

Existing databases should apply:

```powershell
python database\migrations\apply_20260502_flow_search_alert_dedupe_indexes.py
```

## Benchmark

Run the read-only benchmark from the repo root:

```powershell
python scripts\benchmark_flow_log_search.py --runs 5
```

To use search terms from a target environment:

```powershell
python scripts\benchmark_flow_log_search.py --ip-search 10.0.0.10 --app-search Microsoft --domain-search edge.microsoft.com
```

For machine-readable output:

```powershell
python scripts\benchmark_flow_log_search.py --runs 10 --json
```

The benchmark runs these cases:

- `recent`: newest rows without a search term
- `ip_exact`: exact IP search
- `app_prefix`: application prefix search
- `domain_prefix`: host prefix search

Each case reports count query time, page query time, row counts, and `EXPLAIN` output. Use the `key` field in `EXPLAIN` to confirm that MySQL chooses one of the intended indexes.

On the local development dataset with roughly 9k flow rows, a one-run benchmark produced this shape:

- `recent`: page query used `idx_flow_logs_org_last_seen`
- `ip_exact`: page query used `idx_flow_logs_org_last_seen` with IP filtering
- `app_prefix`: page query used index merge across app/domain/SNI indexes
- `domain_prefix`: page query used index merge across domain/SNI/app indexes

That result is acceptable for the current local dataset, but the benchmark should be rerun after large imports or production-like traffic capture. If `ip_exact` remains a hot path at larger sizes, evaluate a UNION-based query plan or additional composite IP indexes.

## Full-Text Decision Rule

Do not add full-text search only because the UI has a search box. Add it when benchmark results show that the current exact/prefix strategy fails a real workflow:

- users need arbitrary contains search across host/application fields
- query plans show table scans at realistic row counts
- prefix search does not satisfy the investigation workflow
- the expected row count justifies index/storage overhead

If those conditions are met, evaluate MySQL `FULLTEXT` against generated normalized text columns before introducing an external search service.
