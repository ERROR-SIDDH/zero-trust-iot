"""
zt_dynamic_trust_scorer.py — Zero Trust IoT: Dynamic per-session trust scorer.

Authors: Muthu Venkatesh M, Dr. Subbulakshmi T, Arun Santhosh R A
VIT Chennai, India

Mirrors: model/zt-dynamic-trust-scorer.h / zt-dynamic-trust-scorer.cc

Tracks per-session packet events and computes a sliding-window trust score.
- Initial packets establish baseline rate.
- Rate deviation > 1.5x baseline triggers violation with exponential penalty: ALPHA * 2^(violations - 1).
- Normal behaviour recovers trust by +BETA.
- If trust drops below THRESHOLD (25.0), session is blocked.
"""

from __future__ import annotations

import collections
import dataclasses
from typing import Dict, Deque, Tuple
from .zt_logger import ZtLogger

try:
    from ns import ns
except ImportError:
    ns = None


@dataclasses.dataclass
class PacketEvent:
    timestamp: float
    protocol: int
    port: int


@dataclasses.dataclass
class TrustState:
    trust_score: float = 100.0
    consecutive_violations: int = 0
    baseline_packet_rate: float = 0.0
    baseline_initialized: bool = False
    window: Deque[PacketEvent] = dataclasses.field(default_factory=collections.deque)
    blocked: bool = False


class ZtDynamicTrustScorer:
    """
    Dynamic trust scorer matching C++ ZtDynamicTrustScorer exactly.
    """

    ALPHA: float = 5.0
    BETA: float = 2.0
    THRESHOLD: float = 25.0
    WINDOW_DURATION: float = 3.0  # seconds

    def __init__(self) -> None:
        # (src_node, dst_node) -> TrustState
        self._trust_table: Dict[Tuple[int, int], TrustState] = {}

    def _get_sim_time(self) -> float:
        if ns is not None:
            try:
                return float(ns.Simulator.Now().GetSeconds())
            except Exception:
                pass
        import time
        return time.time()

    def update_window(self, state: TrustState, protocol: int, dst_port: int, now: float) -> None:
        state.window.append(PacketEvent(timestamp=now, protocol=protocol, port=dst_port))
        while state.window and (now - state.window[0].timestamp) > self.WINDOW_DURATION:
            state.window.popleft()

    def compute_deviation(self, state: TrustState) -> float:
        if not state.window:
            return 0.0
        duration = state.window[-1].timestamp - state.window[0].timestamp
        if duration <= 0:
            return 0.0
        return len(state.window) / duration

    def on_packet_received(self, src_node: int, dst_node: int, protocol: int, dst_port: int) -> None:
        key = (src_node, dst_node)
        state = self._trust_table.setdefault(key, TrustState())

        if state.blocked:
            ZtLogger.log("DTS", "Packet rejected — session blocked")
            return

        now = self._get_sim_time()
        self.update_window(state, protocol, dst_port, now)
        deviation = self.compute_deviation(state)

        if not state.baseline_initialized:
            state.baseline_packet_rate = deviation
            state.baseline_initialized = True
            ZtLogger.log("DTS", "Packet accepted (baseline learning)")
            return

        violation = (deviation > state.baseline_packet_rate * 1.5)

        if violation:
            state.consecutive_violations += 1
            penalty = self.ALPHA * (2 ** (state.consecutive_violations - 1))
            state.trust_score -= penalty

            ZtLogger.log("DTS", "Trust violation detected")
            if state.consecutive_violations > 1:
                ZtLogger.log("DTS", "Repeated trust violation detected")
            ZtLogger.log("DTS", "Packet dropped due to violation")
        else:
            state.consecutive_violations = 0
            state.trust_score += self.BETA
            ZtLogger.log("DTS", "Packet accepted (normal behaviour)")

        # Clamp between 0.0 and 100.0
        state.trust_score = max(0.0, min(100.0, state.trust_score))

        ZtLogger.log("DTS", f"Trust Score ({src_node}->{dst_node}): {state.trust_score}")

        if state.trust_score < self.THRESHOLD:
            ZtLogger.log("DTS", "Trust below threshold — blocking session")
            state.blocked = True

    def is_session_allowed(self, src_node: int, dst_node: int) -> bool:
        key = (src_node, dst_node)
        state = self._trust_table.get(key)
        if state is None:
            return True
        return not state.blocked

    def get_trust_score(self, src_node: int, dst_node: int) -> float:
        key = (src_node, dst_node)
        state = self._trust_table.get(key)
        return state.trust_score if state else 100.0

    def reset_session(self, src_node: int, dst_node: int) -> None:
        self._trust_table.pop((src_node, dst_node), None)
