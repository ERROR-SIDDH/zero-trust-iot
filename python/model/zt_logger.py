"""
zt_logger.py — Zero Trust IoT: Structured logger.

Authors: Arun Santhosh R A, Dr. Subbulakshmi T
VIT Chennai, India

Mirrors: model/zt-logger.h / zt-logger.cc
"""

import time
from typing import Optional


class ZtLogger:
    """
    Centralised, structured logger for Zero Trust simulation events.

    All methods are class-level (no instantiation needed) to replicate
    the static C++ interface.
    """

    _timestamps_enabled: bool = False

    @classmethod
    def enable_timestamps(cls, enabled: bool) -> None:
        """Enable or disable ISO-8601 timestamp prefixes on all log lines."""
        cls._timestamps_enabled = enabled

    @classmethod
    def log(cls, component: str, message: str) -> None:
        """
        Emit a log line in the format  [COMPONENT] message.

        Parameters
        ----------
        component : str
            Short tag identifying the subsystem (e.g. "ZT-CERT").
        message : str
            Human-readable log message.
        """
        prefix = ""
        if cls._timestamps_enabled:
            prefix = f"[{time.strftime('%Y-%m-%dT%H:%M:%S')}] "
        print(f"{prefix}[{component}] {message}")

    @classmethod
    def log_cert_issued(cls, node_id: int, role: str, expiry: int) -> None:
        """Log that a certificate was issued for a node."""
        cls.log("ZT-CERT", f"Certificate issued | Node={node_id} Role={role} Expiry={expiry}")

    @classmethod
    def log_cert_validation_result(cls, node_id: int, valid: bool) -> None:
        """Log the result of certificate validation."""
        result = "VALID" if valid else "INVALID"
        cls.log("ZT-CERT", f"Certificate {result} for Node {node_id}")

    @classmethod
    def log_encryption(cls, payload: str, iv: bytes) -> None:
        """Log that a payload was encrypted."""
        iv_hex = iv.hex() if isinstance(iv, (bytes, bytearray)) else iv
        cls.log("ZT-ENC", f"Encrypted payload: {payload!r} | IV: {iv_hex}")

    @classmethod
    def log_decryption(cls, payload: str) -> None:
        """Log a successfully decrypted payload."""
        cls.log("ZT-DEC", f"Decrypted Payload: {payload}")

    @classmethod
    def log_decryption_failure(cls) -> None:
        """Log a decryption failure."""
        cls.log("ZT-DEC", "Decryption failed: Invalid session or corrupt data")
