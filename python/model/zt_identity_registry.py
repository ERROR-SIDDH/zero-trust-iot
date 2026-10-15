"""
zt_identity_registry.py — Zero Trust IoT: Singleton identity registry.

Authors: Rahul S, Dr. Subbulakshmi T, Arun Santhosh R A
VIT Chennai, India

Mirrors: model/zt-identity-registry.h / zt-identity-registry.cc

Stores a mapping of  node_id → (role, sha256_identity_hash)
and exposes it via a module-level singleton instance.
"""

from __future__ import annotations
from typing import Dict, Optional, Tuple
from .zt_hash_utils import compute_sha256


class IdentityRegistry:
    """
    Singleton registry that maps ns-3 node IDs to their assigned
    role and SHA-256 identity hash.

    Usage
    -----
    registry = IdentityRegistry.get_instance()
    registry.register_node(node_id=0, role="sensor")
    hash_val = registry.get_identity_hash(0)
    role     = registry.get_role(0)
    """

    _instance: Optional["IdentityRegistry"] = None

    def __init__(self) -> None:
        # node_id → (role, identity_hash)
        self._identity_map: Dict[int, Tuple[str, str]] = {}

    @classmethod
    def get_instance(cls) -> "IdentityRegistry":
        """Return the global singleton IdentityRegistry."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset the singleton (useful between simulation runs in tests)."""
        cls._instance = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register_node(self, node_id: int, role: str) -> None:
        """
        Register a node with the given role, computing its SHA-256 hash.

        Parameters
        ----------
        node_id : int
            Unique identifier of the ns-3 node (matches Node.GetId()).
        role : str
            Role string, e.g. "sensor", "gateway", "Camera".
        """
        raw = str(node_id) + role
        identity_hash = compute_sha256(raw)
        self._identity_map[node_id] = (role, identity_hash)

    def get_identity_hash(self, node_id: int) -> str:
        """
        Return the SHA-256 identity hash for *node_id*.

        Returns empty string if node is not registered.
        """
        entry = self._identity_map.get(node_id)
        return entry[1] if entry else ""

    def get_role(self, node_id: int) -> str:
        """
        Return the role assigned to *node_id*.

        Returns empty string if node is not registered.
        """
        entry = self._identity_map.get(node_id)
        return entry[0] if entry else ""
