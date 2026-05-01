from __future__ import annotations

from functools import lru_cache
import logging
import platform
import socket
import threading
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Callable, Optional

logger = logging.getLogger("netvisor.capture")


@lru_cache(maxsize=1)
def _load_scapy_primitives():
    from scapy.all import Ether, sniff  # type: ignore

    return Ether, sniff


class CaptureBackend(ABC):
    def __init__(
        self,
        *,
        role: str,
        interface: str | None = None,
        requested_backend: str = "auto",
        promiscuous: bool = True,
    ) -> None:
        self.role = str(role or "capture")
        self.interface = str(interface or "").strip() or None
        self.requested_backend = str(requested_backend or "auto").strip().lower() or "auto"
        self.promiscuous = bool(promiscuous)
        self._running = False
        self._stop_event = threading.Event()
        self._metrics_lock = threading.Lock()
        self._started_at_ts: Optional[float] = None
        self._last_packet_at_ts: Optional[float] = None
        self._last_emit_at_ts: Optional[float] = None
        self._last_error: Optional[str] = None
        self._seen_packets = 0
        self._emitted_packets = 0
        self._dropped_packets = 0

    @property
    @abstractmethod
    def backend_name(self) -> str:
        raise NotImplementedError

    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    def _format_ts(self, value: Optional[float]) -> Optional[str]:
        if value is None:
            return None
        return datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    def _mark_started(self) -> None:
        with self._metrics_lock:
            self._running = True
            self._started_at_ts = time.time()
            self._last_packet_at_ts = None
            self._last_emit_at_ts = None
            self._last_error = None
            self._seen_packets = 0
            self._emitted_packets = 0
            self._dropped_packets = 0
        self._stop_event.clear()

    def _mark_stopped(self) -> None:
        with self._metrics_lock:
            self._running = False

    def _record_seen(self) -> None:
        now = time.time()
        with self._metrics_lock:
            self._seen_packets += 1
            self._last_packet_at_ts = now

    def _record_emit(self) -> None:
        now = time.time()
        with self._metrics_lock:
            self._emitted_packets += 1
            self._last_emit_at_ts = now

    def _record_drop(self, message: str | None = None) -> None:
        with self._metrics_lock:
            self._dropped_packets += 1
            if message:
                self._last_error = message

    def _normalize_capture_result(self, result) -> bool:
        if result is None:
            return True
        return bool(result)

    def stop(self) -> None:
        self._stop_event.set()
        self._mark_stopped()

    def status_snapshot(self) -> dict:
        with self._metrics_lock:
            started_at = self._started_at_ts
            last_packet_at = self._last_packet_at_ts
            last_emit_at = self._last_emit_at_ts
            last_error = self._last_error
            seen_packets = self._seen_packets
            emitted_packets = self._emitted_packets
            dropped_packets = self._dropped_packets
            running = self._running

        lag_seconds = None
        if last_packet_at is not None:
            lag_seconds = max(time.time() - last_packet_at, 0.0)

        return {
            "requested_backend": self.requested_backend,
            "active_backend": self.backend_name,
            "capture_interface": self.interface,
            "promiscuous": self.promiscuous,
            "running": running,
            "started_at": self._format_ts(started_at),
            "last_packet_at": self._format_ts(last_packet_at),
            "last_emit_at": self._format_ts(last_emit_at),
            "capture_lag_seconds": round(lag_seconds, 3) if lag_seconds is not None else None,
            "packets_seen": seen_packets,
            "packets_emitted": emitted_packets,
            "packets_dropped": dropped_packets,
            "last_error": last_error,
        }

    @abstractmethod
    def start(self, on_packet: Callable[[object], bool], timeout: int | float | None = None) -> tuple[bool, Optional[str]]:
        raise NotImplementedError


class ScapyCaptureBackend(CaptureBackend):
    @property
    def backend_name(self) -> str:
        return "scapy"

    def start(self, on_packet: Callable[[object], bool], timeout: int | float | None = None) -> tuple[bool, Optional[str]]:
        self._mark_started()
        deadline = None if timeout is None else time.time() + max(float(timeout), 0.0)
        try:
            _, sniff = _load_scapy_primitives()
            while not self._stop_event.is_set():
                if deadline is not None:
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        break
                    slice_timeout = min(1.0, remaining)
                else:
                    slice_timeout = 1.0

                def _dispatch(packet) -> None:
                    self._record_seen()
                    try:
                        accepted = self._normalize_capture_result(on_packet(packet))
                    except Exception as exc:
                        self._record_drop(str(exc))
                        logger.debug("Scapy capture callback failed: %s", exc)
                        return
                    if accepted:
                        self._record_emit()
                    else:
                        self._record_drop("filtered")

                sniff(
                    iface=self.interface,
                    store=False,
                    promisc=self.promiscuous,
                    timeout=slice_timeout,
                    prn=_dispatch,
                )
        except Exception as exc:
            self._record_drop(str(exc))
            self._mark_stopped()
            return False, str(exc)

        self._mark_stopped()
        return True, None


class LinuxRawSocketCaptureBackend(CaptureBackend):
    @property
    def backend_name(self) -> str:
        return "linux_raw"

    def start(self, on_packet: Callable[[object], bool], timeout: int | float | None = None) -> tuple[bool, Optional[str]]:
        if platform.system().lower() != "linux":
            message = "Linux raw socket capture is only available on Linux hosts."
            self._record_drop(message)
            self._mark_stopped()
            return False, message

        if not self.interface:
            message = "Linux raw socket capture requires an interface name."
            self._record_drop(message)
            self._mark_stopped()
            return False, message

        self._mark_started()
        deadline = None if timeout is None else time.time() + max(float(timeout), 0.0)
        raw_socket: socket.socket | None = None
        try:
            Ether, _ = _load_scapy_primitives()
            raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            raw_socket.bind((self.interface, 0))
            raw_socket.settimeout(1.0)

            while not self._stop_event.is_set():
                if deadline is not None and time.time() >= deadline:
                    break
                try:
                    raw_frame = raw_socket.recv(65535)
                except socket.timeout:
                    continue
                except OSError as exc:
                    self._record_drop(str(exc))
                    return False, str(exc)

                self._record_seen()
                try:
                    packet = Ether(raw_frame)
                except Exception as exc:
                    self._record_drop(f"decode_error: {exc}")
                    continue

                try:
                    accepted = self._normalize_capture_result(on_packet(packet))
                except Exception as exc:
                    self._record_drop(str(exc))
                    logger.debug("Raw capture callback failed: %s", exc)
                    continue

                if accepted:
                    self._record_emit()
                else:
                    self._record_drop("filtered")
        except Exception as exc:
            self._record_drop(str(exc))
            self._mark_stopped()
            return False, str(exc)
        finally:
            if raw_socket is not None:
                try:
                    raw_socket.close()
                except OSError:
                    pass
            self._mark_stopped()
        return True, None


def build_capture_backend(
    *,
    role: str,
    interface: str | None,
    requested_backend: str = "auto",
    promiscuous: bool = True,
) -> CaptureBackend:
    backend_name = str(requested_backend or "auto").strip().lower() or "auto"
    if backend_name in {"linux", "linux_raw", "native"}:
        return LinuxRawSocketCaptureBackend(
            role=role,
            interface=interface,
            requested_backend=backend_name,
            promiscuous=promiscuous,
        )
    if backend_name in {"scapy", "python"}:
        return ScapyCaptureBackend(
            role=role,
            interface=interface,
            requested_backend=backend_name,
            promiscuous=promiscuous,
        )

    if platform.system().lower() == "linux":
        return LinuxRawSocketCaptureBackend(
            role=role,
            interface=interface,
            requested_backend=backend_name,
            promiscuous=promiscuous,
        )

    return ScapyCaptureBackend(
        role=role,
        interface=interface,
        requested_backend=backend_name,
        promiscuous=promiscuous,
    )
