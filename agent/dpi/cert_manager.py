from __future__ import annotations

import hashlib
import logging
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)


class CertificateManager:
    RECENT_INSTALL_GRACE_SECONDS = 300

    def __init__(self, runtime_dir: Path):
        self.runtime_dir = Path(runtime_dir)
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.key_path = self.runtime_dir / "netvisor-agent-root.key"
        self.cert_path = self.runtime_dir / "netvisor-agent-root.pem"
        self.install_marker_path = self.runtime_dir / "netvisor-agent-root.installed"

    def ensure_ca_files(self) -> None:
        if self.key_path.exists() and self.cert_path.exists():
            return

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NetVisor"),
                x509.NameAttribute(NameOID.COMMON_NAME, "NetVisor Agent Root CA"),
            ]
        )
        now = datetime.now(timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )

        self.key_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        self.cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))

    def certificate_thumbprint(self) -> str | None:
        if not self.cert_path.exists():
            return None
        certificate = x509.load_pem_x509_certificate(self.cert_path.read_bytes())
        return hashlib.sha1(certificate.public_bytes(serialization.Encoding.DER)).hexdigest().upper()

    def _mark_recent_install(self) -> None:
        self.install_marker_path.write_text(datetime.now(timezone.utc).isoformat(), encoding="utf-8")

    def _recent_install_marker(self) -> bool:
        if not self.install_marker_path.exists():
            return False
        try:
            modified = datetime.fromtimestamp(
                self.install_marker_path.stat().st_mtime,
                tz=timezone.utc,
            )
        except OSError:
            return False
        return (datetime.now(timezone.utc) - modified).total_seconds() <= self.RECENT_INSTALL_GRACE_SECONDS

    def _find_powershell(self) -> str | None:
        candidates = [
            Path(os.environ.get("WINDIR", "C:\\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe",
            Path(sys.executable).resolve().parent / "powershell.exe",
        ]
        for candidate in candidates:
            if candidate.exists():
                return str(candidate)
        return None

    def _is_installed_via_powershell(self, thumbprint: str) -> bool:
        powershell = self._find_powershell()
        if not powershell:
            return False
        script = (
            "$thumb='{thumb}'; "
            "$stores=@('Cert:\\CurrentUser\\Root','Cert:\\LocalMachine\\Root'); "
            "$match=$false; "
            "foreach ($store in $stores) {{ "
            "  try {{ "
            "    if (Get-ChildItem $store -ErrorAction Stop | Where-Object {{ $_.Thumbprint -eq $thumb }} | Select-Object -First 1) {{ "
            "      $match=$true; break "
            "    }} "
            "  }} catch {{}} "
            "}}; "
            "if ($match) {{ Write-Output 'FOUND' }} else {{ Write-Output 'MISSING' }}"
        ).format(thumb=thumbprint)
        try:
            result = subprocess.run(
                [powershell, "-NoProfile", "-Command", script],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return "FOUND" in (result.stdout or "")

    def _is_installed_via_certutil(self, thumbprint: str) -> bool:
        try:
            result = subprocess.run(
                ["certutil", "-user", "-store", "Root"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return thumbprint in (result.stdout or "")

    def is_installed(self) -> bool:
        thumbprint = self.certificate_thumbprint()
        if not thumbprint:
            return False
        if self._is_installed_via_powershell(thumbprint):
            return True
        if self._is_installed_via_certutil(thumbprint):
            return True
        return self._recent_install_marker()

    def install_if_needed(self) -> tuple[bool, str | None]:
        self.ensure_ca_files()
        if self.is_installed():
            return True, None
        try:
            result = subprocess.run(
                ["certutil", "-user", "-addstore", "Root", str(self.cert_path)],
                capture_output=True,
                text=True,
                check=False,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            logger.warning("Timed out waiting for NetVisor CA install confirmation.")
            return False, "Timed out waiting for certificate approval"
        except (OSError, subprocess.SubprocessError) as exc:
            logger.warning("Failed to install NetVisor CA: %s", exc)
            return False, str(exc)

        if result.returncode != 0:
            message = (result.stderr or result.stdout or "Certificate install failed").strip()
            logger.warning("certutil failed to install NetVisor CA: %s", message)
            return False, message

        self._mark_recent_install()
        return self.is_installed(), None

    def status(self) -> dict:
        self.ensure_ca_files()
        return {
            "ca_file_exists": self.cert_path.exists(),
            "ca_installed": self.is_installed(),
            "cert_path": str(self.cert_path),
        }
