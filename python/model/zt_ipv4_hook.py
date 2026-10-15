"""
zt_ipv4_hook.py — Zero Trust IoT: IPv4-layer policy hook.

Authors: Rahul S, Dr. Subbulakshmi T, Arun Santhosh R A
VIT Chennai, India

Mirrors: model/zt-ipv4-hook.h / zt-ipv4-hook.cc

In the C++ version this class hooks into ns-3's IPv4 Tx trace.
In the Python version, this is a lightweight wrapper that:
  1. Holds a reference to the policy engine.
  2. Exposes an intercept_packet() method called from simulation callbacks.
  3. Assumes destination is always node 1 (mirrors the C++ demo assumption).
"""

from __future__ import annotations

from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .zt_policy_engine import ZtPolicyEngine


class ZtIpv4Hook:
    """
    IPv4-layer Zero Trust hook.

    Attach to a node and call :meth:`intercept_packet` whenever the
    node transmits a packet.  The hook consults the policy engine and
    prints ALLOW/DENY decisions.

    Mirrors the C++ ``ZtIpv4Hook`` ns3::Object.
    """

    def __init__(self) -> None:
        self._engine: Optional["ZtPolicyEngine"] = None
        self._node_id: Optional[int] = None
        self._dst_node_id: int = 1   # default destination (mirrors C++ demo)

    def set_policy_engine(self, engine: "ZtPolicyEngine") -> None:
        """Attach a policy engine for access-control decisions."""
        self._engine = engine

    def attach_to_node(self, node_id: int, dst_node_id: int = 1) -> None:
        """
        Attach this hook to *node_id*.

        Parameters
        ----------
        node_id : int
            Source node whose outgoing traffic is monitored.
        dst_node_id : int
            Default destination node ID (used in the demo / micro-seg check).
        """
        self._node_id = node_id
        self._dst_node_id = dst_node_id

    def intercept_packet(self, action: str = "TRANSFER") -> None:
        """
        Evaluate policy for a packet being transmitted by the attached node.

        Parameters
        ----------
        action : str
            The action to evaluate (default ``"TRANSFER"``).
        """
        if self._engine is None or self._node_id is None:
            return

        decision = self._engine.evaluate_micro_segmentation(
            self._node_id,
            self._dst_node_id,
            action,
        )

        if decision:
            print(f"[ZT-NETWORK] Policy ALLOW at IP layer (node {self._node_id} → {self._dst_node_id})")
        else:
            print(f"[ZT-NETWORK] Policy DENY at IP layer (node {self._node_id} → {self._dst_node_id})")
