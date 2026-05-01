from app.api.agents import _lookup_agent_organization_id


class _FakeCursor:
    def __init__(self, row=None):
        self.row = row
        self.calls = []

    def execute(self, query, params=None):
        self.calls.append((" ".join(query.split()), params))

    def fetchone(self):
        return self.row


def test_lookup_agent_organization_id_queries_agents_primary_key():
    cursor = _FakeCursor({"organization_id": "org-123"})

    organization_id = _lookup_agent_organization_id(cursor, "AGENT-1")

    assert organization_id == "org-123"
    assert cursor.calls == [
        (
            "SELECT organization_id FROM agents WHERE id = %s LIMIT 1",
            ("AGENT-1",),
        )
    ]
