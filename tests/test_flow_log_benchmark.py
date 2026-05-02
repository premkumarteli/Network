from scripts.benchmark_flow_log_search import _case_queries


def test_benchmark_case_queries_use_shared_flow_log_contract():
    count_sql, count_params, page_sql, page_params = _case_queries(
        "org-1",
        {"search": "10.0.0.10"},
        limit=25,
        offset=50,
    )

    assert count_sql.startswith("SELECT COUNT(*) AS total FROM flow_logs WHERE organization_id = %s")
    assert "src_ip = %s" in count_sql
    assert "LIKE" not in count_sql
    assert "ORDER BY last_seen DESC" in page_sql
    assert count_params == ["org-1", "10.0.0.10", "10.0.0.10", "10.0.0.10", "10.0.0.10"]
    assert page_params == [*count_params, 25, 50]
