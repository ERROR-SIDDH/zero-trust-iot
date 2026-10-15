"""
micro-segmentation-test.py — Zero Trust IoT: Micro-segmentation demo.

Authors: Rahul S, Dr. Subbulakshmi T, Arun Santhosh R A
VIT Chennai, India

Mirrors: examples/micro-segmentation-test.cc

Demonstrates role-based micro-segmentation with:
  • Camera → AnalyticsServer STREAM rule (all hours, rate-limited to 5)
  • MaintenanceDevice → AnalyticsServer UPDATE rule (2–4 AM only)
  • Default DENY for all unknown actions (e.g. REBOOT)
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
from model import ZtPolicyEngine, RolePolicyRule, RuleEffect, IdentityRegistry

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    # --- Create 3 virtual nodes (IDs 0, 1, 2) via ns-3 NodeContainer ---
    nodes = ns.NodeContainer()
    nodes.Create(3)

    camera_id     = nodes.Get(0).GetId()
    analytics_id  = nodes.Get(1).GetId()
    maintenance_id = nodes.Get(2).GetId()

    # --- Register identities ---
    registry = IdentityRegistry.get_instance()
    registry.register_node(camera_id,      "Camera")
    registry.register_node(analytics_id,   "AnalyticsServer")
    registry.register_node(maintenance_id, "MaintenanceDevice")

    # --- Build policy engine ---
    engine = ZtPolicyEngine()

    # Camera → AnalyticsServer  STREAM  (all-day, max 5 per 30 s)
    stream_rule = RolePolicyRule(
        src_role="Camera",
        dst_role="AnalyticsServer",
        action="STREAM",
        start_hour=0,
        end_hour=24,
        window_seconds=30,
        max_transfers=5,
        effect=RuleEffect.ALLOW,
    )
    engine.add_role_policy_rule(stream_rule)

    # MaintenanceDevice → AnalyticsServer  UPDATE  (2 AM – 4 AM only)
    update_rule = RolePolicyRule(
        src_role="MaintenanceDevice",
        dst_role="AnalyticsServer",
        action="UPDATE",
        start_hour=2,
        end_hour=4,
        window_seconds=60,
        max_transfers=2,
        effect=RuleEffect.ALLOW,
    )
    engine.add_role_policy_rule(update_rule)

    print("\n--- Dynamic Trust Enforcement Demo ---")

    # 1. Valid streaming
    d1 = engine.evaluate_micro_segmentation(camera_id, analytics_id, "STREAM")
    print(f"Camera STREAM → {'ALLOW' if d1 else 'DENY'}")

    # 2. Exceed stream threshold
    for _ in range(6):
        engine.evaluate_micro_segmentation(camera_id, analytics_id, "STREAM")

    d2 = engine.evaluate_micro_segmentation(camera_id, analytics_id, "STREAM")
    print(f"Camera Excess STREAM → {'ALLOW' if d2 else 'DENY'}")

    # 3. Maintenance (DENY unless current hour is 2–4)
    d3 = engine.evaluate_micro_segmentation(maintenance_id, analytics_id, "UPDATE")
    print(f"Maintenance UPDATE → {'ALLOW' if d3 else 'DENY'}")

    # 4. Unknown action → always DENY (least-privilege default)
    d4 = engine.evaluate_micro_segmentation(camera_id, analytics_id, "REBOOT")
    print(f"Camera REBOOT → {'ALLOW' if d4 else 'DENY'}")

    print(f"\nPolicy version  : {engine.get_policy_version()}")
    print(f"Policy integrity: {engine.get_policy_integrity_hash()}")

    # ns-3 cleanup (no network traffic needed for this test)
    ns.Simulator.Run()
    ns.Simulator.Destroy()

    # Clean up singleton for next run
    IdentityRegistry.reset()


if __name__ == "__main__":
    main()
