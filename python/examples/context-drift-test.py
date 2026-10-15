"""
context-drift-test.py — Zero Trust IoT: Context Drift Validator demonstration.

Authors: Rahul R, Dr. Subbulakshmi T, Arun Santhosh R A
VIT Chennai, India

Mirrors: examples/context-drift-test.cc

Simulates IoT node behaviour with deterministic context data:
  • Node 1 → Perfectly normal (no drift)
  • Node 2 → Mild drift
  • Node 3 → Severe drift
  • Node 4 → Normal until t=8s, then a rare extreme attack
"""

import sys
import os

# ---------------------------------------------------------------------------
# NS-3 Python bootstrap
# ---------------------------------------------------------------------------
NS3_DIR = os.path.expanduser("~/Desktop/ns-allinone-3.46.1/ns-3.46.1")
sys.path.insert(0, NS3_DIR)

try:
    from ns import ns
except ModuleNotFoundError:
    raise SystemExit(
        "Error: ns3 Python module not found; "
        "Python bindings may not be enabled or PYTHONPATH not configured."
    )

# ---------------------------------------------------------------------------
# Zero Trust model imports
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from model import (
    ZtLogger,
    ZtPolicyEngine,
    ContextAttributeStore,
    PeriodicRevalidator,
    schedule,
)

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------
NODES = [1, 2, 3, 4]
rare_attack: bool = False
g_store: ContextAttributeStore
g_validator: PeriodicRevalidator


def update_context() -> None:
    """Push deterministic context updates for each node (called every second)."""
    for node_id in NODES:
        if rare_attack and node_id == 4:
            time_ctx, congestion, proximity = 23, 0.99, 15
            ZtLogger.log("CONTEXT-DRIFT-TEST", "Extreme drift (Node 4)")
        elif node_id == 3:
            time_ctx, congestion, proximity = 18, 0.75, 8
            ZtLogger.log("CONTEXT-DRIFT-TEST", "Severe drift (Node 3)")
        elif node_id == 2:
            time_ctx, congestion, proximity = 12, 0.30, 3
            ZtLogger.log("CONTEXT-DRIFT-TEST", "Mild drift (Node 2)")
        else:
            time_ctx, congestion, proximity = 10, 0.10, 2
            ZtLogger.log("CONTEXT-DRIFT-TEST", "Normal behavior (Node 1)")

        g_store.update_current_context(node_id, time_ctx, congestion, proximity)

    schedule(ns.Seconds(1.0), update_context)


def validate_loop() -> None:
    """Run one revalidation cycle (called every second)."""
    g_validator.revalidate()
    schedule(ns.Seconds(1.0), validate_loop)


def trigger_rare_attack() -> None:
    """Activate the rare extreme attack on Node 4."""
    global rare_attack
    rare_attack = True
    ZtLogger.log("CONTEXT-DRIFT-TEST", ">>> RARE ATTACK ACTIVATED <<<")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    global g_store, g_validator

    ns.Time.SetResolution(ns.Time.NS)

    policy = ZtPolicyEngine()
    store = ContextAttributeStore()

    for n in NODES:
        policy.add_authorized(n, "generic-device")
        policy.authorize(n, "generic-device")
        store.store_baseline(n, 10.0, 0.10, 2)

    validator = PeriodicRevalidator(policy, store)
    validator.set_parameters(
        wt=0.35,
        wc=0.35,
        wp=0.30,
        lambda_=0.05,
        threshold=0.40,
    )
    for n in NODES:
        validator.add_active_node(n)

    g_store = store
    g_validator = validator

    schedule(ns.Seconds(1.0), update_context)
    schedule(ns.Seconds(2.0), validate_loop)
    schedule(ns.Seconds(8.0), trigger_rare_attack)

    ns.Simulator.Stop(ns.Seconds(18.0))
    ns.Simulator.Run()
    ns.Simulator.Destroy()


if __name__ == "__main__":
    main()
