from __future__ import annotations

import sys

import agent.main as agent_main_module
import gateway.main as gateway_main_module
from run_server import perform_health_check


def test_server_probe_mode_returns_success():
    assert perform_health_check() == 0


def test_agent_probe_mode_returns_success(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["run_agent.py", "--health-check"])

    try:
        agent_main_module.main()
    except SystemExit as exc:
        assert exc.code == 0
    else:
        raise AssertionError("agent probe mode did not exit")


def test_gateway_probe_mode_returns_success(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["run_gateway.py", "--health-check"])

    try:
        gateway_main_module.main()
    except SystemExit as exc:
        assert exc.code == 0
    else:
        raise AssertionError("gateway probe mode did not exit")
