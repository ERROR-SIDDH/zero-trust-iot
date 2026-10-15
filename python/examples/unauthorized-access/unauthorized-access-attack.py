"""
unauthorized-access-attack.py — Zero Trust IoT: Unauthorized Access Attack scenario.

Authors: Arun Santhosh R A, Dr. Subbulakshmi T
VIT Chennai, India

Mirrors: examples/unauthorized-access/unauthorized-access-attack.cc

Topology:
  Node 0 (sensor)  ──p2p──  Node 1 (sink/server)
  Node 2 (attacker) ──p2p── Node 1

Scenario:
  • Sensor authenticates with a valid cert and sends an encrypted payload.
  • Attacker has NO certificate and attempts to send a malicious payload.
  • Sink rejects attacker's packet (no cert, no session key).
"""

import sys
import os
import time

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
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
from model import (
    ZtLogger,
    ZtPolicyEngine,
    CertificateAuthority,
    ZtTlsHandshake,
    encrypt_payload,
    decrypt_payload,
    hex_to_bytes,
    schedule,
)

ZtLogger.enable_timestamps(True)

# ---------------------------------------------------------------------------
# Zero Trust components (shared across Application callbacks)
# ---------------------------------------------------------------------------
ca       = CertificateAuthority()
policy   = ZtPolicyEngine()
handshake = ZtTlsHandshake()

policy.set_ca_public_key(ca.get_public_key())
policy.add_authorized(0, "sensor")

# Track which nodes have been authorised at the sink
authorized: dict[int, bool] = {}


# ---------------------------------------------------------------------------
# Application helpers
# ---------------------------------------------------------------------------
def sensor_start() -> None:
    """Sensor: issue cert, perform handshake, schedule encrypted send."""
    expiry = int(time.time()) + 60
    cert = ca.sign_identity(0, "sensor", expiry)
    ZtLogger.log_cert_issued(0, "sensor", expiry)

    # Deliver cert to sink (simulated)
    sink_receive_cert(cert)

    handshake.start_handshake(client_id=0, server_id=1)
    schedule(ns.Seconds(2.0), sensor_send_encrypted)


def sensor_send_encrypted() -> None:
    """Sensor: encrypt payload and deliver to sink."""
    if not handshake.has_session(0):
        ZtLogger.log("ZT", "Sensor node has no session key – skipping encryption")
        return

    session_key = handshake.get_session_key(0)
    raw_key = hex_to_bytes(session_key)
    payload = "TEMP:25.5"
    cipher_with_iv, iv = encrypt_payload(payload, raw_key)
    ZtLogger.log_encryption(payload, iv)

    # Deliver to sink (simulated)
    sink_receive_data(cipher_with_iv, sender_id=0)


def attacker_send() -> None:
    """Attacker: send raw malicious payload (no cert, no session)."""
    ZtLogger.log("ATTACKER", "Sending unauthorized payload")
    sink_receive_data(b"ERASE:ALL", sender_id=2)


# ---------------------------------------------------------------------------
# Sink logic
# ---------------------------------------------------------------------------
def sink_receive_cert(cert_str: str) -> None:
    """Sink: validate an incoming certificate."""
    try:
        # Parse nodeId from cert
        id_part = cert_str.split("|")[0]
        node_id = int(id_part.split(":")[1])
        role_part = [t for t in cert_str.split("|") if t.startswith("ROLE:")][0]
        role = role_part.split(":")[1]

        valid = policy.authorize_with_cert(node_id, role, cert_str)
        ZtLogger.log_cert_validation_result(node_id, valid)
        authorized[node_id] = valid

        if valid:
            handshake.start_handshake(client_id=node_id, server_id=1)
    except Exception as e:
        ZtLogger.log("ZT", f"Malformed certificate – ignored ({e})")


def sink_receive_data(data: bytes, sender_id: int) -> None:
    """Sink: attempt to decrypt an incoming data packet."""
    if authorized.get(sender_id) and handshake.has_session(sender_id):
        try:
            session_key = handshake.get_session_key(sender_id)
            raw_key = hex_to_bytes(session_key)
            decrypted = decrypt_payload(data, raw_key)
            ZtLogger.log_decryption(decrypted)
        except Exception:
            ZtLogger.log_decryption_failure()
    else:
        ZtLogger.log("ZT", f"Unauthorized data attempt from node {sender_id} - dropped")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    # Build topology (3 nodes, point-to-point)
    nodes = ns.NodeContainer()
    nodes.Create(3)

    p2p = ns.PointToPointHelper()
    p2p.SetDeviceAttribute("DataRate", ns.StringValue("5Mbps"))
    p2p.SetChannelAttribute("Delay", ns.StringValue("2ms"))
    p2p.Install(nodes.Get(0), nodes.Get(1))
    p2p.Install(nodes.Get(2), nodes.Get(1))

    stack = ns.InternetStackHelper()
    stack.Install(nodes)

    ip = ns.Ipv4AddressHelper()
    ip.SetBase(ns.Ipv4Address("10.1.1.0"), ns.Ipv4Mask("255.255.255.0"))
    ip.Assign(ns.NetDeviceContainer(nodes.Get(0).GetDevice(0), nodes.Get(1).GetDevice(0)))
    ip.SetBase(ns.Ipv4Address("10.1.2.0"), ns.Ipv4Mask("255.255.255.0"))
    ip.Assign(ns.NetDeviceContainer(nodes.Get(2).GetDevice(0), nodes.Get(1).GetDevice(1)))

    # Schedule Zero Trust events
    schedule(ns.Seconds(1.0), sensor_start)
    schedule(ns.Seconds(2.5), attacker_send)

    ns.Simulator.Stop(ns.Seconds(20.0))
    ns.Simulator.Run()
    ns.Simulator.Destroy()


if __name__ == "__main__":
    main()
