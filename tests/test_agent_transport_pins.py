import json

from app.core.config import settings
from app.services.agent_auth_service import agent_auth_service


def test_transport_pins_filters_invalid_entries(monkeypatch):
    monkeypatch.setattr(
        settings,
        "BACKEND_TLS_PINS_JSON",
        json.dumps(
            [
                {"pin_type": "spki_sha256", "pin_sha256": "A" * 64, "status": "active"},
                {"pin_type": "cert_sha256", "pin_sha256": "b" * 64, "status": "next"},
                {"pin_type": "bogus", "pin_sha256": "C" * 64, "status": "active"},
                {"pin_type": "spki_sha256", "pin_sha256": "short", "status": "active"},
                {"pin_type": "spki_sha256", "pin_sha256": "D" * 64, "status": "retired"},
            ]
        ),
    )

    pins = agent_auth_service.transport_pins()

    assert pins == [
        {"pin_type": "spki_sha256", "pin_sha256": "A" * 64, "status": "active"},
        {"pin_type": "cert_sha256", "pin_sha256": "B" * 64, "status": "next"},
    ]
