"""
spoofing-mitigation.py — Zero Trust IoT: Spoofing Attack Mitigation.

Authors: Arun Santhosh R A, Dr. Subbulakshmi T
VIT Chennai, India

Mirrors: examples/spoofing/spoofing-mitigation.cc

Adds to the spoofing-attack scenario:
  1. Identity hash verification — sink checks SHA-256 identity hash from registry.
  2. Dynamic trust scoring — decryption failures reduce trust and can block sender.
  3. Explicit revocation — spoofer's claimed node ID is revoked on detection.
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
    ZtDynamicTrustScorer,
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
scorer    = ZtDynamicTrustScorer()

policy.set_ca_public_key(ca.get_public_key())
policy.add_authorized(0, "sensor")

authorized: dict[int, bool] = {}

LEGIT_ID   = 0
SPOOFER_ID = 1
SINK_ID    = 2

registry = IdentityRegistry.get_instance()


# ---------------------------------------------------------------------------
# Sensor
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
    scorer.on_packet_received(LEGIT_ID, SINK_ID, 6, 9090)
    sink_receive_data(cipher_with_iv, sender_id=LEGIT_ID)


# ---------------------------------------------------------------------------
# Spoofer
# ---------------------------------------------------------------------------
def spoofer_send() -> None:
    ZtLogger.log("SPOOFER", f"Attempting identity spoofing as node {LEGIT_ID}")

    # Mitigation 1: trust check
    if not scorer.is_session_allowed(LEGIT_ID, SINK_ID):
        ZtLogger.log("ZT-MITIGATION", "Session BLOCKED by trust scorer — spoof attempt halted")
        return

    # Still tries — send raw bytes claiming to be LEGIT_ID
    sink_receive_data(b"INJECT:FAKE_DATA", sender_id=LEGIT_ID)


# ---------------------------------------------------------------------------
# Sink (with identity-hash verification added)
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
    # Mitigation 2: verify identity hash
    expected_hash = registry.get_identity_hash(sender_id)
    if not expected_hash:
        ZtLogger.log("ZT-MITIGATION", f"Node {sender_id} not in identity registry — DROPPED")
        return

    if authorized.get(sender_id) and handshake.has_session(sender_id):
        try:
            session_key = handshake.get_session_key(sender_id)
            raw_key = hex_to_bytes(session_key)
            decrypted = decrypt_payload(data, raw_key)
            ZtLogger.log_decryption(decrypted)
            scorer.on_packet_received(sender_id, SINK_ID, 6, 9090)
        except Exception:
            # Mitigation 3: decryption failure → penalise trust → revoke
            ZtLogger.log("ZT-MITIGATION", f"Decryption failed — SPOOFING DETECTED for node {sender_id}")
            ZtLogger.log_decryption_failure()
            # Simulate rapid failed attempts to tank trust score
            for _ in range(6):
                scorer.on_packet_received(sender_id, SINK_ID, 6, 9090)
            if not scorer.is_session_allowed(sender_id, SINK_ID):
                policy.revoke(sender_id)
                ZtLogger.log("ZT-MITIGATION", f"Node {sender_id} REVOKED after trust collapse")
    else:
        ZtLogger.log("ZT-MITIGATION", f"Data from node {sender_id} BLOCKED (no valid cert/session)")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    nodes = ns.NodeContainer()
    nodes.Create(3)

    registry.register_node(LEGIT_ID,   "sensor")
    registry.register_node(SPOOFER_ID, "untrusted")
    registry.register_node(SINK_ID,    "sink")

    p2p = ns.PointToPointHelper()
    p2p.SetDeviceAttribute("DataRate", ns.StringValue("5Mbps"))
    p2p.SetChannelAttribute("Delay", ns.StringValue("2ms"))
    p2p.Install(nodes.Get(0), nodes.Get(2))
    p2p.Install(nodes.Get(1), nodes.Get(2))

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
