"""
mitm-mitigation.py — Zero Trust IoT: MITM Attack Mitigation.

Authors: Arun Santhosh R A, Dr. Subbulakshmi T
VIT Chennai, India

Mirrors: examples/mitm/mitm-mitigation.cc

Same topology as mitm-attack.py, but mitigation adds:
  1. Dynamic trust scoring — rapid decryption failures lower trust.
  2. Micro-segmentation — MITM node (role "untrusted") is denied TRANSFER.
  3. Session key binding — forged certs from unknown CA are rejected.
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
    RolePolicyRule,
    RuleEffect,
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

# Register identities for micro-seg
registry = IdentityRegistry.get_instance()
# Node IDs are determined at runtime — we use placeholders here and update in main()
SENSOR_ID = 0
MITM_ID   = 1
SINK_ID   = 2

# Micro-segmentation: only sensor → sink TRANSFER is allowed
seg_rule = RolePolicyRule(
    src_role="sensor",
    dst_role="sink",
    action="TRANSFER",
    start_hour=0,
    end_hour=24,
    window_seconds=60,
    max_transfers=20,
    effect=RuleEffect.ALLOW,
)
# MITM rule: explicitly DENY
mitm_rule = RolePolicyRule(
    src_role="untrusted",
    dst_role="sink",
    action="*",
    start_hour=0,
    end_hour=24,
    window_seconds=60,
    max_transfers=0,
    effect=RuleEffect.DENY,
)


# ---------------------------------------------------------------------------
# Sensor (node 0)
# ---------------------------------------------------------------------------
def sensor_start() -> None:
    expiry = int(time.time()) + 60
    cert = ca.sign_identity(SENSOR_ID, "sensor", expiry)
    ZtLogger.log_cert_issued(SENSOR_ID, "sensor", expiry)
    sink_receive_cert(cert)
    handshake.start_handshake(client_id=SENSOR_ID, server_id=SINK_ID)
    schedule(ns.Seconds(2.0), sensor_send_encrypted)


def sensor_send_encrypted() -> None:
    if not handshake.has_session(SENSOR_ID):
        ZtLogger.log("ZT", "Sensor: no session key – aborting")
        return

    # Micro-seg check before sending
    if not policy.evaluate_micro_segmentation(SENSOR_ID, SINK_ID, "TRANSFER"):
        ZtLogger.log("ZT", "Sensor TRANSFER denied by micro-segmentation")
        return

    session_key = handshake.get_session_key(SENSOR_ID)
    raw_key = hex_to_bytes(session_key)
    payload = "TEMP:25.5"
    cipher_with_iv, iv = encrypt_payload(payload, raw_key)
    ZtLogger.log_encryption(payload, iv)
    scorer.on_packet_received(SENSOR_ID, SINK_ID, 6, 9090)
    mitm_intercept_and_relay(cipher_with_iv)


# ---------------------------------------------------------------------------
# MITM (node 1) — mitigation active
# ---------------------------------------------------------------------------
def mitm_intercept_and_relay(data: bytes) -> None:
    ZtLogger.log("MITM", "Intercepted packet — attempting relay")

    # Check micro-seg: MITM (untrusted) → sink is DENIED
    allowed = policy.evaluate_micro_segmentation(MITM_ID, SINK_ID, "TRANSFER")
    if not allowed:
        ZtLogger.log("ZT-MITIGATION", "MITM TRANSFER denied by micro-segmentation")
        return

    # Check dynamic trust
    if not scorer.is_session_allowed(MITM_ID, SINK_ID):
        ZtLogger.log("ZT-MITIGATION", "MITM session BLOCKED by trust scorer")
        return

    # If MITM gets past all gates (it shouldn't), attempt data injection
    fake_ca = CertificateAuthority()
    fake_cert = fake_ca.sign_identity(SENSOR_ID, "sensor", int(time.time()) + 60)
    sink_receive_cert(fake_cert)
    sink_receive_data(b"TEMP:99.9", sender_id=MITM_ID)


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
            handshake.start_handshake(client_id=node_id, server_id=SINK_ID)
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
            scorer.on_packet_received(sender_id, SINK_ID, 6, 9090)
    else:
        ZtLogger.log("ZT-MITIGATION", f"Data from node {sender_id} BLOCKED (no cert/session)")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    nodes = ns.NodeContainer()
    nodes.Create(3)

    registry.register_node(SENSOR_ID, "sensor")
    registry.register_node(MITM_ID,   "untrusted")
    registry.register_node(SINK_ID,   "sink")

    policy.add_role_policy_rule(seg_rule)
    policy.add_role_policy_rule(mitm_rule)

    p2p = ns.PointToPointHelper()
    p2p.SetDeviceAttribute("DataRate", ns.StringValue("5Mbps"))
    p2p.SetChannelAttribute("Delay", ns.StringValue("2ms"))
    p2p.Install(nodes.Get(0), nodes.Get(1))
    p2p.Install(nodes.Get(1), nodes.Get(2))

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

    IdentityRegistry.reset()


if __name__ == "__main__":
    main()
