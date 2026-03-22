from __future__ import annotations

import os
import subprocess
from pathlib import Path


BROWSER_CANDIDATES = {
    "chrome.exe": [
        Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "Google/Chrome/Application/chrome.exe",
        Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")) / "Google/Chrome/Application/chrome.exe",
        Path(os.environ.get("LocalAppData", "")) / "Google/Chrome/Application/chrome.exe",
    ],
    "msedge.exe": [
        Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "Microsoft/Edge/Application/msedge.exe",
        Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")) / "Microsoft/Edge/Application/msedge.exe",
        Path(os.environ.get("LocalAppData", "")) / "Microsoft/Edge/Application/msedge.exe",
    ],
}


class BrowserLauncher:
    def __init__(self, runtime_dir: Path, proxy_port: int):
        self.runtime_dir = Path(runtime_dir)
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.proxy_port = int(proxy_port)

    def _profile_dir(self, label: str) -> Path:
        profile_dir = self.runtime_dir / "browser-profiles" / label
        profile_dir.mkdir(parents=True, exist_ok=True)
        return profile_dir

    def _find_executable(self, process_name: str) -> Path | None:
        for candidate in BROWSER_CANDIDATES.get(process_name, []):
            if candidate and candidate.exists():
                return candidate
        return None

    def create_wrappers(self) -> dict[str, str]:
        wrapper_paths = {}
        for process_name, label in (("chrome.exe", "chrome"), ("msedge.exe", "edge")):
            executable = self._find_executable(process_name)
            wrapper_path = self.runtime_dir / f"launch_{label}_netvisor.cmd"
            profile_dir = self._profile_dir(label)
            if executable:
                wrapper_path.write_text(
                    "\n".join(
                        [
                            "@echo off",
                            f"set NETVISOR_PROXY=http://127.0.0.1:{self.proxy_port}",
                            f"set NETVISOR_PROFILE_DIR={profile_dir}",
                            f"start \"NetVisor {label.title()}\" \"{executable}\" --new-window --user-data-dir=\"%NETVISOR_PROFILE_DIR%\" --proxy-server=%NETVISOR_PROXY% %*",
                        ]
                    ),
                    encoding="utf-8",
                )
            else:
                wrapper_path.write_text(
                    "\n".join(
                        [
                            "@echo off",
                            f"echo {process_name} was not found on this device.",
                            "exit /b 1",
                        ]
                    ),
                    encoding="utf-8",
                )
            wrapper_paths[process_name] = str(wrapper_path)
        return wrapper_paths

    def launch(self, process_name: str, url: str | None = None) -> bool:
        executable = self._find_executable(process_name)
        if not executable:
            return False
        label = "edge" if process_name.lower() == "msedge.exe" else "chrome"
        args = [
            str(executable),
            "--new-window",
            f"--user-data-dir={self._profile_dir(label)}",
            f"--proxy-server=http://127.0.0.1:{self.proxy_port}",
        ]
        if url:
            args.append(url)
        try:
            subprocess.Popen(args)
            return True
        except OSError:
            return False
