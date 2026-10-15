"""
trust-scorer-test.py — Zero Trust IoT: Dynamic Trust Scorer demonstration.

Authors: Muthu Venkatesh M, Dr. Subbulakshmi T, Arun Santhosh R A
VIT Chennai, India

Mirrors: examples/trust-scorer-test.cc

Simulates IoT node packet bursts to demonstrate:
  • Exponential penalty for consecutive violations (burst traffic)
  • Gradual trust recovery for normal traffic
  • Session blocking when trust falls below threshold
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
        "Python bindings may not be enabled or PYTHONPATH not configured.\n"
        "Run: cd ~/Desktop/ns-allinone-3.46.1/ns-3.46.1 && "
        "./ns3 configure --enable-python-bindings && ./ns3 build"
    )

# ---------------------------------------------------------------------------
# Zero Trust model imports (relative to this file's location)
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from model import ZtDynamicTrustScorer, schedule

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------
scorer = ZtDynamicTrustScorer()

SRC = 0
DST = 1


def send_normal() -> None:
    """Simulate a single normal packet (triggers recovery)."""
    print("Normal packet")
    scorer.on_packet_received(SRC, DST, 6, 8080)


def send_burst() -> None:
    """Simulate a rapid burst of 5 packets (triggers violations)."""
    print("Violation burst")
    for i in range(5):
        schedule(
            ns.MilliSeconds(i * 50),
            lambda: scorer.on_packet_received(SRC, DST, 6, 8080),
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    schedule(ns.Seconds(1.0), send_normal)
    schedule(ns.Seconds(2.0), send_normal)
    schedule(ns.Seconds(3.0), send_burst)
    schedule(ns.Seconds(7.0), send_normal)
    schedule(ns.Seconds(8.0), send_burst)

    ns.Simulator.Stop(ns.Seconds(15.0))
    ns.Simulator.Run()
    ns.Simulator.Destroy()


if __name__ == "__main__":
    main()
