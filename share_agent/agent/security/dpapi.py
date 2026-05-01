from __future__ import annotations

import ctypes
import os


CRYPTPROTECT_UI_FORBIDDEN = 0x01


class DataProtector:
    def protect(self, data: bytes, *, description: str = "") -> bytes:
        raise NotImplementedError

    def unprotect(self, data: bytes) -> bytes:
        raise NotImplementedError


class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", ctypes.c_uint),
        ("pbData", ctypes.POINTER(ctypes.c_byte)),
    ]


class WindowsCurrentUserProtector(DataProtector):
    def __init__(self) -> None:
        self._available = os.name == "nt"
        if self._available:
            self._crypt32 = ctypes.windll.crypt32
            self._kernel32 = ctypes.windll.kernel32

    def _require_windows(self) -> None:
        if not self._available:
            raise RuntimeError("Windows DPAPI is only available on Windows agents.")

    def _bytes_from_blob(self, blob: DATA_BLOB) -> bytes:
        try:
            return ctypes.string_at(blob.pbData, blob.cbData)
        finally:
            if blob.pbData:
                self._kernel32.LocalFree(blob.pbData)

    def protect(self, data: bytes, *, description: str = "") -> bytes:
        self._require_windows()
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("DPAPI protector expects bytes")

        input_buffer = ctypes.create_string_buffer(bytes(data), len(data))
        input_blob = DATA_BLOB(len(data), ctypes.cast(input_buffer, ctypes.POINTER(ctypes.c_byte)))
        output_blob = DATA_BLOB()
        description_value = ctypes.c_wchar_p(description or "")
        success = self._crypt32.CryptProtectData(
            ctypes.byref(input_blob),
            description_value,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(output_blob),
        )
        if not success:
            raise ctypes.WinError()
        return self._bytes_from_blob(output_blob)

    def unprotect(self, data: bytes) -> bytes:
        self._require_windows()
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("DPAPI protector expects bytes")

        input_buffer = ctypes.create_string_buffer(bytes(data), len(data))
        input_blob = DATA_BLOB(len(data), ctypes.cast(input_buffer, ctypes.POINTER(ctypes.c_byte)))
        output_blob = DATA_BLOB()
        success = self._crypt32.CryptUnprotectData(
            ctypes.byref(input_blob),
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(output_blob),
        )
        if not success:
            raise ctypes.WinError()
        return self._bytes_from_blob(output_blob)
