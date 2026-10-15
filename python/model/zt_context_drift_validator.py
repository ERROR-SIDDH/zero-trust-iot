"""
zt_context_drift_validator.py — Zero Trust IoT: Continuous context drift monitoring.

Authors: Rahul R, Dr. Subbulakshmi T, Arun Santhosh R A
VIT Chennai, India

Mirrors: model/zt-context-drift-validator.h / zt-context-drift-validator.cc

Even after a node is authenticated and authorised, its access is NOT permanent.
The node's operational context is continuously monitored. If the context drifts
too far from the baseline captured during handshake, trust is gradually reduced
and access is revoked via the policy engine.
"""

from __future__ import annotations

import math
from typing import Dict, Optional, Set, TYPE_CHECKING

if TYPE_CHECKING:
    from .zt_policy_engine import ZtPolicyEngine


class ContextAttributeStore:
    """
    Stores baseline and runtime context attributes for nodes.

    Attributes tracked per node
    ---------------------------
    time_of_day  : float   — normalised hour-of-day context value
    congestion   : float   — network congestion level [0.0, 1.0]
    proximity    : int     — physical proximity indicator
    trust_score  : float   — decayed trust value [0.0, 1.0]

    Mirrors the C++ ``ContextAttributeStore`` class.
    """

    def __init__(self) -> None:
        self._baseline_time: Dict[int, float] = {}
        self._baseline_congestion: Dict[int, float] = {}
        self._baseline_proximity: Dict[int, int] = {}

        self._current_time: Dict[int, float] = {}
        self._current_congestion: Dict[int, float] = {}
        self._current_proximity: Dict[int, int] = {}

        self._trust_score: Dict[int, float] = {}

    # ------------------------------------------------------------------
    # Baseline capture
    # ------------------------------------------------------------------

    def store_baseline(
        self,
        node_id: int,
        time_of_day: float,
        congestion: float,
        proximity: int,
    ) -> None:
        """
        Capture the baseline operating context for *node_id* at onboarding time.

        Trust score is initialised to 1.0 (fully trusted).
        """
        self._baseline_time[node_id] = time_of_day
        self._baseline_congestion[node_id] = congestion
        self._baseline_proximity[node_id] = proximity

        # Current context starts at baseline
        self._current_time[node_id] = time_of_day
        self._current_congestion[node_id] = congestion
        self._current_proximity[node_id] = proximity

        self._trust_score[node_id] = 1.0

    # ------------------------------------------------------------------
    # Runtime updates
    # ------------------------------------------------------------------

    def update_current_context(
        self,
        node_id: int,
        time_of_day: float,
        congestion: float,
        proximity: int,
    ) -> None:
        """Update the live operational context for *node_id*."""
        self._current_time[node_id] = time_of_day
        self._current_congestion[node_id] = congestion
        self._current_proximity[node_id] = proximity

    # ------------------------------------------------------------------
    # Drift & trust calculation
    # ------------------------------------------------------------------

    def calculate_drift(
        self,
        node_id: int,
        wt: float,
        wc: float,
        wp: float,
    ) -> float:
        """
        Compute the weighted drift between baseline and current context.

        Drift formula (mirrors C++ CalculateDrift):
            Δ = wt·|dt| + wc·|dc| + wp·|dp|

        Parameters
        ----------
        wt : float   Weight for time-of-day deviation.
        wc : float   Weight for congestion deviation.
        wp : float   Weight for proximity deviation.
        """
        dt = abs(self._current_time.get(node_id, 0) - self._baseline_time.get(node_id, 0))
        dc = abs(self._current_congestion.get(node_id, 0) - self._baseline_congestion.get(node_id, 0))
        dp = abs(float(self._current_proximity.get(node_id, 0)) - float(self._baseline_proximity.get(node_id, 0)))

        return wt * dt + wc * dc + wp * dp

    def update_trust(self, node_id: int, drift: float, lambda_: float) -> None:
        """
        Apply exponential trust decay proportional to drift.

        Trust formula (mirrors C++ UpdateTrust):
            T(t+1) = T(t) · e^(−λ · drift)
        """
        current = self._trust_score.get(node_id, 1.0)
        updated = current * math.exp(-lambda_ * drift)
        self._trust_score[node_id] = max(0.0, updated)

    def get_trust(self, node_id: int) -> float:
        """Return the current trust score for *node_id* (0.0–1.0)."""
        return self._trust_score.get(node_id, 0.0)


# ---------------------------------------------------------------------------


class PeriodicRevalidator:
    """
    Periodically evaluates node trust and revokes low-trust nodes.

    Mirrors the C++ ``PeriodicRevalidator`` class.

    Parameters
    ----------
    policy : ZtPolicyEngine
        Policy engine used to revoke compromised nodes.
    store : ContextAttributeStore
        Context store holding baseline/current data and trust scores.
    """

    def __init__(
        self,
        policy: "ZtPolicyEngine",
        store: ContextAttributeStore,
    ) -> None:
        self._policy = policy
        self._store = store
        self._active_nodes: Set[int] = set()

        # Revalidation parameters
        self._wt: float = 0.0
        self._wc: float = 0.0
        self._wp: float = 0.0
        self._lambda: float = 0.0
        self._trust_threshold: float = 0.0

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def set_parameters(
        self,
        wt: float,
        wc: float,
        wp: float,
        lambda_: float,
        threshold: float,
    ) -> None:
        """
        Set weighting and decay parameters for drift/trust evaluation.

        Parameters
        ----------
        wt        Weight for time-of-day drift.
        wc        Weight for congestion drift.
        wp        Weight for proximity drift.
        lambda_   Decay rate for trust update (λ in the exponential).
        threshold Trust score below which a node is revoked.
        """
        self._wt = wt
        self._wc = wc
        self._wp = wp
        self._lambda = lambda_
        self._trust_threshold = threshold

    def add_active_node(self, node_id: int) -> None:
        """Register a node for periodic revalidation."""
        self._active_nodes.add(node_id)

    # ------------------------------------------------------------------
    # Revalidation
    # ------------------------------------------------------------------

    def revalidate(self) -> None:
        """
        Run one revalidation cycle over all active nodes.

        For each node: compute drift → update trust → revoke if below threshold.
        """
        for node_id in self._active_nodes:
            drift = self._store.calculate_drift(node_id, self._wt, self._wc, self._wp)
            self._store.update_trust(node_id, drift, self._lambda)
            trust = self._store.get_trust(node_id)

            print(
                f"[ZeroTrust] Node {node_id}"
                f" Drift={drift:.4f}"
                f" Trust={trust:.4f}"
            )

            if trust < self._trust_threshold:
                self._policy.revoke(node_id)
                print(
                    f"[ZeroTrust] Node {node_id}"
                    " revoked due to low trust"
                )
