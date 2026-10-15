"""
zt_tls_handshake.py — Zero Trust IoT: Simulated TLS-like handshake.

Authors: Arun Santhosh R A, Dr. Subbulakshmi T
VIT Chennai, India

Mirrors: model/zt-tls-handshake.h / zt-tls-handshake.cc

Generates random AES session keys and stores them keyed by peer node ID,
mirroring the C++ ZtTlsHandshake ns3::Object.
"""

from __future__ import annotations

from typing import Callable, Dict, Optional
from .zt_encryption_utils import generate_session_key, session_key_to_hex
from .zt_logger import ZtLogger


class ZtTlsHandshake:
    """
    Simulated TLS-like handshake that negotiates a shared AES session key
    between a client and server node.

    Mirrors the C++ ``ZtTlsHandshake`` ns3::Object.
    """

    def __init__(self) -> None:
        # peer_node_id → hex-encoded session key
        self._session_keys: Dict[int, str] = {}
        self._logger: Optional[Callable[[str], None]] = None
        self._policy_validator: Optional[Callable[[int, str], bool]] = None

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def set_external_logger(self, logger: Callable[[str], None]) -> None:
        """Set an external logging callback (overrides default ZtLogger)."""
        self._logger = logger

    def set_policy_validator(self, validator: Callable[[int, str], bool]) -> None:
        """
        Set a callback that validates (node_id, role) before handshake.

        Signature: validator(node_id: int, role: str) -> bool
        """
        self._policy_validator = validator

    # ------------------------------------------------------------------
    # Handshake
    # ------------------------------------------------------------------

    def start_handshake(
        self,
        client_id: int,
        server_id: int,
    ) -> bool:
        """
        Perform a simulated handshake between *client_id* and *server_id*.

        Both nodes share the same randomly generated AES-128 session key.
        If a policy validator is registered, both nodes are checked before
        the key is generated.

        Parameters
        ----------
        client_id : int
            Node ID of the client.
        server_id : int
            Node ID of the server.

        Returns
        -------
        bool
            ``True`` if the session was established.
        """
        if self._policy_validator:
            if not self._policy_validator(client_id, "client"):
                self._log("[ZT-HANDSHAKE] Client not authorized by policy")
                return False
            if not self._policy_validator(server_id, "server"):
                self._log("[ZT-HANDSHAKE] Server not authorized by policy")
                return False

        raw_key = generate_session_key()
        hex_key = session_key_to_hex(raw_key)

        self._session_keys[server_id] = hex_key
        self._session_keys[client_id] = hex_key

        self._log(
            f"[ZT-HANDSHAKE] Session established between Client {client_id}"
            f" and Server {server_id} | Key: {hex_key}"
        )
        return True

    # ------------------------------------------------------------------
    # Session queries
    # ------------------------------------------------------------------

    def has_session(self, peer_id: int) -> bool:
        """Return ``True`` if a session key exists for *peer_id*."""
        return peer_id in self._session_keys

    def get_session_key(self, peer_id: int) -> str:
        """
        Return the hex-encoded session key for *peer_id*.

        Returns empty string if no session exists.
        """
        return self._session_keys.get(peer_id, "")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _log(self, msg: str) -> None:
        if self._logger:
            self._logger(msg)
        else:
            ZtLogger.log("ZT-TLS", msg)
