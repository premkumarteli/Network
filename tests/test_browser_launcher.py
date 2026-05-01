from pathlib import Path

from agent.dpi.browser_launcher import BrowserLauncher


def test_browser_launcher_creates_dedicated_profile_wrapper(monkeypatch, tmp_path):
    launcher = BrowserLauncher(tmp_path, 8899)
    fake_browser = tmp_path / "chrome.exe"
    fake_browser.write_text("", encoding="utf-8")

    monkeypatch.setattr(
        launcher,
        "_find_executable",
        lambda process_name: fake_browser if process_name == "chrome.exe" else None,
    )

    wrapper_paths = launcher.create_wrappers()
    wrapper_text = Path(wrapper_paths["chrome.exe"]).read_text(encoding="utf-8")

    assert "--new-window" in wrapper_text
    assert "--user-data-dir=" in wrapper_text
    assert "--proxy-server=%NETVISOR_PROXY%" in wrapper_text
    assert "--disable-quic" in wrapper_text
