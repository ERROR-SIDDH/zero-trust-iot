"""
spoofing-attack.py — Zero Trust IoT: IP/Identity Spoofing Attack scenario.

Authors: Arun Santhosh R A, Dr. Subbulakshmi T
VIT Chennai, India

Mirrors: examples/spoofing/spoofing-attack.cc

Topology:
  Node 0 (legitimate sensor) ──p2p── Node 2 (sink)
  Node 1 (spoofer)           ──p2p── Node 2 (sink)

Scenario:
  • Legitimate sensor registers with the identity registry and sends traffic.
  • Spoofer claims to be the sensor (same node_id=0) but has no cert and
    no valid session key — the sink rejects it.
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
    IdentityRegistry,
    encrypt_payload,
    decrypt_payload,
    hex_to_bytes,
    schedule,
)

ZtLogger.enable_timestamps(True)

# ---------------------------------------------------------------------------
# Zero Trust components
# ---------------------------------------------------------------------------
ca        = CertificateAuthority()
policy    = ZtPolicyEngine()
handshake = ZtTlsHandshake()

policy.set_ca_public_key(ca.get_public_key())
policy.add_authorized(0, "sensor")

authorized: dict[int, bool] = {}

LEGIT_ID   = 0
SPOOFER_ID = 1   # real ID of the attacker node
SINK_ID    = 2


# ---------------------------------------------------------------------------
# Legitimate sensor
# ---------------------------------------------------------------------------
def sensor_start() -> None:
    expiry = int(time.time()) + 60
    cert = ca.sign_identity(LEGIT_ID, "sensor", expiry)
    ZtLogger.log_cert_issued(LEGIT_ID, "sensor", expiry)
    sink_receive_cert(cert)
    handshake.start_handshake(client_id=LEGIT_ID, server_id=SINK_ID)
    schedule(ns.Seconds(2.0), sensor_send_encrypted)


def sensor_send_encrypted() -> None:
    if not handshake.has_session(LEGIT_ID):
        return
    session_key = handshake.get_session_key(LEGIT_ID)
    raw_key = hex_to_bytes(session_key)
    payload = "TEMP:25.5"
    cipher_with_iv, iv = encrypt_payload(payload, raw_key)
    ZtLogger.log_encryption(payload, iv)
    sink_receive_data(cipher_with_iv, sender_id=LEGIT_ID)


# ---------------------------------------------------------------------------
# Spoofer (node 1) — claims to be LEGIT_ID=0
# ---------------------------------------------------------------------------
def spoofer_send() -> None:
    ZtLogger.log("SPOOFER", f"Claiming to be sensor node {LEGIT_ID} — sending raw payload")
    # Tries to inject without a valid cert or session key
    sink_receive_data(b"INJECT:FAKE_DATA", sender_id=LEGIT_ID)


# ---------------------------------------------------------------------------
# Sink
# ---------------------------------------------------------------------------
def sink_receive_cert(cert_str: str) -> None:
    try:
        id_part = cert_str.split("|")[0]
        node_id = int(id_part.split(":")[1])
        role_part = [t for t in cert_str.split("|") if t.startswith("ROLE:")][0]
        role = role_part.split(":")[1]
        valid = policy.authorize_with_cert(node_id, role, cert_str)
        ZtLogger.log_cert_validation_result(node_id, valid)
        authorized[node_id] = valid
        if valid:
            handshake.start_handshake(client_id=node_id, server_id=SINK_ID)
    except Exception as e:
        ZtLogger.log("ZT", f"Malformed certificate – ignored ({e})")


def sink_receive_data(data: bytes, sender_id: int) -> None:
    """
    Note: In the spoofer scenario sender_id=LEGIT_ID is claimed by spoofer.
    The session key mismatch will cause decryption to fail — exposing the attack.
    """
    if authorized.get(sender_id) and handshake.has_session(sender_id):
        try:
            session_key = handshake.get_session_key(sender_id)
            raw_key = hex_to_bytes(session_key)
            decrypted = decrypt_payload(data, raw_key)
            ZtLogger.log_decryption(decrypted)
        except Exception:
            ZtLogger.log("ZT-SPOOF", f"Decryption failed for claimed node {sender_id} — SPOOFING DETECTED")
            ZtLogger.log_decryption_failure()
    else:
        ZtLogger.log("ZT", f"Data rejected (no valid cert/session) for node {sender_id}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    nodes = ns.NodeContainer()
    nodes.Create(3)   # 0=sensor, 1=spoofer, 2=sink

    registry = IdentityRegistry.get_instance()
    registry.register_node(LEGIT_ID,   "sensor")
    registry.register_node(SPOOFER_ID, "untrusted")
    registry.register_node(SINK_ID,    "sink")

    p2p = ns.PointToPointHelper()
    p2p.SetDeviceAttribute("DataRate", ns.StringValue("5Mbps"))
    p2p.SetChannelAttribute("Delay", ns.StringValue("2ms"))
    p2p.Install(nodes.Get(0), nodes.Get(2))   # sensor ─ sink
    p2p.Install(nodes.Get(1), nodes.Get(2))   # spoofer ─ sink

    stack = ns.InternetStackHelper()
    stack.Install(nodes)

    ip = ns.Ipv4AddressHelper()
    ip.SetBase(ns.Ipv4Address("10.1.1.0"), ns.Ipv4Mask("255.255.255.0"))
    ip.Assign(ns.NetDeviceContainer(nodes.Get(0).GetDevice(0), nodes.Get(2).GetDevice(0)))
    ip.SetBase(ns.Ipv4Address("10.1.2.0"), ns.Ipv4Mask("255.255.255.0"))
    ip.Assign(ns.NetDeviceContainer(nodes.Get(1).GetDevice(0), nodes.Get(2).GetDevice(1)))

    schedule(ns.Seconds(1.0), sensor_start)
    schedule(ns.Seconds(3.0), spoofer_send)

    ns.Simulator.Stop(ns.Seconds(15.0))
    ns.Simulator.Run()
    ns.Simulator.Destroy()

    IdentityRegistry.reset()


if __name__ == "__main__":
    main()
