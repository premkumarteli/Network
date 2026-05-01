from __future__ import annotations

import hashlib
import json
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

from ..security import DataProtector, WindowsCurrentUserProtector

logger = logging.getLogger(__name__)


class CertificateManager:
    RUNTIME_BUNDLE_FILES = (
        "mitmproxy-ca.pem",
        "mitmproxy-ca-cert.pem",
        "mitmproxy-ca-privkey.pem",
    )

    def __init__(self, runtime_dir: Path, *, protector: DataProtector | None = None):
        self.runtime_dir = Path(runtime_dir)
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.protector = protector or WindowsCurrentUserProtector()
        self.key_path = self.runtime_dir / "netvisor-agent-root.key.dpapi"
        self.cert_path = self.runtime_dir / "netvisor-agent-root.pem"
        self.metadata_path = self.runtime_dir / "netvisor-agent-root.meta.json"

    def _utc_now(self) -> datetime:
        return datetime.now(timezone.utc)

    def _find_powershell(self) -> str | None:
        candidates = [
            Path(os.environ.get("WINDIR", "C:\\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe",
            Path(sys.executable).resolve().parent / "powershell.exe",
        ]
        for candidate in candidates:
            if candidate.exists():
                return str(candidate)
        return None

    def _find_icacls(self) -> str | None:
        candidate = Path(os.environ.get("WINDIR", "C:\\Windows")) / "System32/icacls.exe"
        return str(candidate) if candidate.exists() else None

    def _load_certificate(self) -> x509.Certificate | None:
        if not self.cert_path.exists():
            return None
        return x509.load_pem_x509_certificate(self.cert_path.read_bytes())

    def _as_utc(self, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def _not_valid_before(self, certificate: x509.Certificate) -> datetime:
        modern = getattr(certificate, "not_valid_before_utc", None)
        return modern if modern is not None else certificate.not_valid_before

    def _not_valid_after(self, certificate: x509.Certificate) -> datetime:
        modern = getattr(certificate, "not_valid_after_utc", None)
        return modern if modern is not None else certificate.not_valid_after

    def _certificate_metadata(self, certificate: x509.Certificate) -> dict:
        issued_at = self._as_utc(self._not_valid_before(certificate))
        expires_at = self._as_utc(self._not_valid_after(certificate))
        rotation_due_at = expires_at - timedelta(days=30)
        now = self._utc_now()
        days_until_expiry = max(int((expires_at - now).total_seconds() // 86400), 0)
        days_until_rotation_due = max(int((rotation_due_at - now).total_seconds() // 86400), 0)
        return {
            "thumbprint_sha256": hashlib.sha256(
                certificate.public_bytes(serialization.Encoding.DER)
            ).hexdigest().upper(),
            "issued_at": issued_at.isoformat(),
            "expires_at": expires_at.isoformat(),
            "installed_at": None,
            "rotation_due_at": rotation_due_at.isoformat(),
            "days_until_expiry": days_until_expiry,
            "days_until_rotation_due": days_until_rotation_due,
            "expires_soon": days_until_expiry <= 30,
            "rotation_due_soon": days_until_rotation_due <= 7,
            "trust_scope": "CurrentUserRoot",
            "trust_store_match": False,
            "key_protection": "dpapi_user",
            "status": "ready",
        }

    def _write_metadata(self, metadata: dict) -> None:
        self.metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    def _load_metadata(self) -> dict:
        if not self.metadata_path.exists():
            certificate = self._load_certificate()
            return self._certificate_metadata(certificate) if certificate else {}
        try:
            loaded = json.loads(self.metadata_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return loaded if isinstance(loaded, dict) else {}

    def ensure_ca_files(self) -> None:
        if self.key_path.exists() and self.cert_path.exists():
            certificate = self._load_certificate()
            if certificate and not self.metadata_path.exists():
                self._write_metadata(self._certificate_metadata(certificate))
            return

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NetVisor"),
                x509.NameAttribute(NameOID.COMMON_NAME, "NetVisor Agent Root CA"),
            ]
        )
        now = self._utc_now()
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )

        key_bytes = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        protected_key = self.protector.protect(key_bytes, description="netvisor-agent-root-key")
        self.key_path.write_bytes(protected_key)
        self.cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        self._write_metadata(self._certificate_metadata(certificate))

    def certificate_thumbprint_sha256(self) -> str | None:
        certificate = self._load_certificate()
        if not certificate:
            return None
        return hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest().upper()

    def load_private_key_bytes(self) -> bytes:
        self.ensure_ca_files()
        return self.protector.unprotect(self.key_path.read_bytes())

    def _is_currentuser_root_match(self, thumbprint_sha256: str) -> bool:
        powershell = self._find_powershell()
        if not powershell:
            return False
        script = (
            "$expected='{thumb}'; "
            "$now=Get-Date; "
            "$match=$false; "
            "Get-ChildItem 'Cert:\\CurrentUser\\Root' -ErrorAction SilentlyContinue | ForEach-Object {{ "
            "  try {{ "
            "    $sha=[System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash($_.RawData)).Replace('-', ''); "
            "    if ($sha -eq $expected -and $_.NotBefore -le $now -and $_.NotAfter -ge $now) {{ $match=$true }} "
            "  }} catch {{}} "
            "}}; "
            "if ($match) {{ Write-Output 'FOUND' }} else {{ Write-Output 'MISSING' }}"
        ).format(thumb=thumbprint_sha256)
        try:
            result = subprocess.run(
                [powershell, "-NoProfile", "-Command", script],
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return "FOUND" in (result.stdout or "")

    def is_installed(self) -> bool:
        thumbprint = self.certificate_thumbprint_sha256()
        if not thumbprint:
            return False
        return self._is_currentuser_root_match(thumbprint)

    def install_if_needed(self) -> tuple[bool, str | None]:
        self.ensure_ca_files()
        if self.is_installed():
            metadata = self._load_metadata()
            if metadata:
                metadata["installed_at"] = metadata.get("installed_at") or self._utc_now().isoformat()
                metadata["trust_store_match"] = True
                metadata["status"] = "installed"
                self._write_metadata(metadata)
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

        installed = self.is_installed()
        metadata = self._load_metadata()
        if metadata:
            metadata["installed_at"] = self._utc_now().isoformat() if installed else metadata.get("installed_at")
            metadata["trust_store_match"] = installed
            metadata["status"] = "installed" if installed else "mismatch"
            self._write_metadata(metadata)
        return installed, None if installed else "Certificate installed but trust-store verification failed"

    def _apply_user_only_acl(self, path: Path) -> None:
        icacls = self._find_icacls()
        if not icacls:
            return
        username = os.environ.get("USERNAME")
        if not username:
            return
        try:
            subprocess.run(
                [
                    icacls,
                    str(path),
                    "/inheritance:r",
                    f"/grant:r",
                    f"{username}:(R,W)",
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            logger.debug("Failed to tighten ACLs on %s", path)

    def prepare_runtime_bundle(self, target_dir: Path) -> None:
        self.ensure_ca_files()
        self.cleanup_runtime_bundle(target_dir)
        target_dir = Path(target_dir)
        target_dir.mkdir(parents=True, exist_ok=True)

        combined_path = target_dir / "mitmproxy-ca.pem"
        cert_only_path = target_dir / "mitmproxy-ca-cert.pem"
        key_data = self.load_private_key_bytes().strip()
        cert_data = self.cert_path.read_bytes().strip()
        combined_path.write_bytes(key_data + b"\n" + cert_data + b"\n")
        cert_only_path.write_bytes(cert_data + b"\n")
        self._apply_user_only_acl(combined_path)
        self._apply_user_only_acl(cert_only_path)

    def cleanup_runtime_bundle(self, target_dir: Path) -> None:
        for name in self.RUNTIME_BUNDLE_FILES:
            path = Path(target_dir) / name
            try:
                path.unlink(missing_ok=True)
            except OSError:
                continue

    def status(self) -> dict:
        self.ensure_ca_files()
        certificate = self._load_certificate()
        metadata = self._load_metadata()
        if not certificate:
            return {
                "ca_file_exists": False,
                "ca_installed": False,
                "ca_status": "missing",
                "cert_path": str(self.cert_path),
                "thumbprint_sha256": None,
            }

        now = self._utc_now()
        issued_at = self._as_utc(self._not_valid_before(certificate))
        expires_at = self._as_utc(self._not_valid_after(certificate))
        rotation_due_at = expires_at - timedelta(days=30)
        days_until_expiry = max(int((expires_at - now).total_seconds() // 86400), 0)
        days_until_rotation_due = max(int((rotation_due_at - now).total_seconds() // 86400), 0)
        trust_store_match = self.is_installed()
        if now > expires_at:
            status = "expired"
        elif trust_store_match:
            status = "installed"
        else:
            status = "ready"

        metadata.update(
            {
                "thumbprint_sha256": self.certificate_thumbprint_sha256(),
                "issued_at": issued_at.isoformat(),
                "expires_at": expires_at.isoformat(),
                "rotation_due_at": rotation_due_at.isoformat(),
                "days_until_expiry": days_until_expiry,
                "days_until_rotation_due": days_until_rotation_due,
                "expires_soon": days_until_expiry <= 30,
                "rotation_due_soon": days_until_rotation_due <= 7,
                "trust_scope": "CurrentUserRoot",
                "trust_store_match": trust_store_match,
                "key_protection": "dpapi_user",
                "status": status,
            }
        )
        self._write_metadata(metadata)
        return {
            "ca_file_exists": True,
            "ca_installed": trust_store_match,
            "ca_status": status,
            "cert_path": str(self.cert_path),
            "thumbprint_sha256": metadata.get("thumbprint_sha256"),
            "issued_at": metadata.get("issued_at"),
            "expires_at": metadata.get("expires_at"),
            "installed_at": metadata.get("installed_at"),
            "rotation_due_at": metadata.get("rotation_due_at"),
            "days_until_expiry": metadata.get("days_until_expiry"),
            "days_until_rotation_due": metadata.get("days_until_rotation_due"),
            "expires_soon": metadata.get("expires_soon"),
            "rotation_due_soon": metadata.get("rotation_due_soon"),
            "trust_scope": metadata.get("trust_scope"),
            "trust_store_match": metadata.get("trust_store_match"),
            "key_protection": metadata.get("key_protection"),
        }
