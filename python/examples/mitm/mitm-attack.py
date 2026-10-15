"""
mitm-attack.py — Zero Trust IoT: Man-in-the-Middle Attack scenario.

Authors: Arun Santhosh R A, Dr. Subbulakshmi T
VIT Chennai, India

Mirrors: examples/mitm/mitm-attack.cc

Topology:
  Node 0 (sensor) ──p2p── Node 1 (MITM attacker) ──p2p── Node 2 (sink)

Scenario:
  • Sensor sends a legitimate encrypted packet toward the sink.
  • The MITM node intercepts it, fabricates a forged certificate,
    and attempts to relay a modified payload to the sink.
  • The sink's cert verification and session key check rejects the forgery.
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
# Zero Trust components
# ---------------------------------------------------------------------------
ca        = CertificateAuthority()
policy    = ZtPolicyEngine()
handshake = ZtTlsHandshake()

policy.set_ca_public_key(ca.get_public_key())
policy.add_authorized(0, "sensor")

authorized: dict[int, bool] = {}


# ---------------------------------------------------------------------------
# Sensor (node 0)
# ---------------------------------------------------------------------------
def sensor_start() -> None:
    expiry = int(time.time()) + 60
    cert = ca.sign_identity(0, "sensor", expiry)
    ZtLogger.log_cert_issued(0, "sensor", expiry)

    # Cert is intercepted by MITM (node 1) — but MITM forwards it unmodified first
    sink_receive_cert(cert)
    handshake.start_handshake(client_id=0, server_id=2)
    schedule(ns.Seconds(2.0), sensor_send_encrypted)


def sensor_send_encrypted() -> None:
    if not handshake.has_session(0):
        ZtLogger.log("ZT", "Sensor: no session key – aborting")
        return

    session_key = handshake.get_session_key(0)
    raw_key = hex_to_bytes(session_key)
    payload = "TEMP:25.5"
    cipher_with_iv, iv = encrypt_payload(payload, raw_key)
    ZtLogger.log_encryption(payload, iv)

    # MITM intercepts this packet, cannot decrypt (wrong key), forwards tampered data
    mitm_intercept_and_relay(cipher_with_iv)


# ---------------------------------------------------------------------------
# MITM (node 1)
# ---------------------------------------------------------------------------
def mitm_intercept_and_relay(data: bytes) -> None:
    ZtLogger.log("MITM", "Intercepted encrypted packet — cannot decrypt (no session key)")
    ZtLogger.log("MITM", "Forging certificate and relaying tampered payload")

    # Attempt to fabricate a cert (signed by a *different* CA — will fail verification)
    fake_ca = CertificateAuthority()
    fake_cert = fake_ca.sign_identity(0, "sensor", int(time.time()) + 60)

    # Push forged cert to sink
    sink_receive_cert(fake_cert)

    # Relay tampered payload  (MITM doesn't have the correct session key)
    tampered = b"TEMP:99.9"   # fabricated content
    sink_receive_data(tampered, sender_id=0)


# ---------------------------------------------------------------------------
# Sink (node 2)
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
            handshake.start_handshake(client_id=node_id, server_id=2)
    except Exception as e:
        ZtLogger.log("ZT", f"Malformed certificate – ignored ({e})")


def sink_receive_data(data: bytes, sender_id: int) -> None:
    if authorized.get(sender_id) and handshake.has_session(sender_id):
        try:
            session_key = handshake.get_session_key(sender_id)
            raw_key = hex_to_bytes(session_key)
            decrypted = decrypt_payload(data, raw_key)
            ZtLogger.log_decryption(decrypted)
        except Exception:
            ZtLogger.log_decryption_failure()
    else:
        ZtLogger.log("ZT", f"Data from node {sender_id} rejected (no valid session)")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    nodes = ns.NodeContainer()
    nodes.Create(3)   # 0=sensor, 1=mitm, 2=sink

    p2p = ns.PointToPointHelper()
    p2p.SetDeviceAttribute("DataRate", ns.StringValue("5Mbps"))
    p2p.SetChannelAttribute("Delay", ns.StringValue("2ms"))
    p2p.Install(nodes.Get(0), nodes.Get(1))   # sensor ─ mitm
    p2p.Install(nodes.Get(1), nodes.Get(2))   # mitm  ─ sink

    stack = ns.InternetStackHelper()
    stack.Install(nodes)

    ip = ns.Ipv4AddressHelper()
    ip.SetBase(ns.Ipv4Address("10.1.1.0"), ns.Ipv4Mask("255.255.255.0"))
    ip.Assign(ns.NetDeviceContainer(nodes.Get(0).GetDevice(0), nodes.Get(1).GetDevice(0)))
    ip.SetBase(ns.Ipv4Address("10.1.2.0"), ns.Ipv4Mask("255.255.255.0"))
    ip.Assign(ns.NetDeviceContainer(nodes.Get(1).GetDevice(1), nodes.Get(2).GetDevice(0)))

    schedule(ns.Seconds(1.0), sensor_start)

    ns.Simulator.Stop(ns.Seconds(15.0))
    ns.Simulator.Run()
    ns.Simulator.Destroy()


if __name__ == "__main__":
    main()
