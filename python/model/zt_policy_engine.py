"""
zt_policy_engine.py — Zero Trust IoT: Core policy engine.

Authors: Rahul S, Dr. Subbulakshmi T, Arun Santhosh R A
VIT Chennai, India

Mirrors: model/zt-policy-engine.h / zt-policy-engine.cc

Implements:
  - Basic role-based authorisation (AddAuthorized / Authorize)
  - RSA certificate-based authorisation (AuthorizeWithCert)
  - Micro-segmentation with time-windows and rate-limiting (EvaluateMicroSegmentation)
  - Policy integrity hashing (GetPolicyVersion / GetPolicyIntegrityHash)
"""

from __future__ import annotations

import time
import base64
import dataclasses
from enum import IntEnum
from typing import Dict, List, Optional, Set
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

from .zt_hash_utils import compute_sha256
from .zt_identity_registry import IdentityRegistry


class RuleEffect(IntEnum):
    ALLOW = 0
    DENY = 1


@dataclasses.dataclass
class RolePolicyRule:
    """
    A single micro-segmentation policy rule.

    Attributes
    ----------
    src_role : str
        Source node role (e.g. "Camera").
    dst_role : str
        Destination node role (e.g. "AnalyticsServer").
    action : str
        Action string or ``"*"`` for wildcard (e.g. "STREAM", "UPDATE").
    start_hour : int
        Hour of day (0–23) from which the rule is active.
    end_hour : int
        Hour of day (exclusive) until which the rule is active.
    window_seconds : int
        Sliding time-window for rate-limiting (seconds).
    max_transfers : int
        Maximum allowed transfers within *window_seconds*.
    effect : RuleEffect
        ``ALLOW`` or ``DENY``.
    """

    src_role: str
    dst_role: str
    action: str
    start_hour: int
    end_hour: int
    window_seconds: int
    max_transfers: int
    effect: RuleEffect


class ZtPolicyEngine:
    """
    Combined Zero Trust policy engine.

    Manages basic auth, certificate-based auth, and micro-segmentation.
    Mirrors the C++ ``ZtPolicyEngine`` ns3::Object.
    """

    ALLOW = RuleEffect.ALLOW
    DENY = RuleEffect.DENY

    def __init__(self) -> None:
        # Basic auth table: node_id → role
        self._auth_table: Dict[int, str] = {}
        # Revoked node IDs
        self._revoked: Set[int] = set()
        # CA public key for cert verification
        self._ca_public_key = None
        # Micro-segmentation rules
        self._rules: List[RolePolicyRule] = []
        # Transfer history: node_id → list of unix timestamps
        self._transfer_history: Dict[int, List[float]] = {}
        # Policy version / integrity
        self._policy_version: int = 0

    # ------------------------------------------------------------------
    # Basic auth
    # ------------------------------------------------------------------

    def add_authorized(self, node_id: int, role: str) -> None:
        """Register a node as authorised with the given role."""
        self._auth_table[node_id] = role

    def authorize(self, node_id: int, role: str) -> bool:
        """Return ``True`` if *node_id* is authorised with *role*."""
        return self._auth_table.get(node_id) == role

    # ------------------------------------------------------------------
    # Certificate-based auth
    # ------------------------------------------------------------------

    def set_ca_public_key(self, public_key) -> None:
        """Set the CA public key used for certificate-based authorisation."""
        self._ca_public_key = public_key

    def revoke(self, node_id: int) -> None:
        """Revoke a node ID from all future authorisation."""
        self._revoked.add(node_id)

    def authorize_with_cert(self, node_id: int, role: str, cert_str: str) -> bool:
        """
        Validate an RSA-signed certificate and authorise the node.

        Parameters
        ----------
        node_id : int
            Node's claimed ID.
        role : str
            Node's claimed role.
        cert_str : str
            Certificate string in the form produced by CertificateAuthority.

        Returns
        -------
        bool
            ``True`` if the certificate is valid, not revoked, not expired.
        """
        if node_id in self._revoked:
            print(f"ZT-CERT: Node {node_id} is revoked")
            return False

        sig_marker = "|SIG:"
        sig_pos = cert_str.find(sig_marker)
        if sig_pos == -1:
            return False

        content = cert_str[:sig_pos]
        encoded_sig = cert_str[sig_pos + len(sig_marker):]

        try:
            signature = base64.b64decode(encoded_sig)
            self._ca_public_key.verify(
                signature,
                content.encode("utf-8"),
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA1()),
                    salt_length=asym_padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA1(),
            )
        except (InvalidSignature, Exception):
            print("ZT-CERT: Signature invalid")
            return False

        # Parse certificate fields
        id_parsed: Optional[int] = None
        role_parsed: Optional[str] = None
        expiry: Optional[int] = None

        for token in content.split("|"):
            if token.startswith("ID:"):
                try:
                    id_parsed = int(token[3:])
                except ValueError:
                    pass
            elif token.startswith("ROLE:"):
                role_parsed = token[5:]
            elif token.startswith("EXP:"):
                try:
                    expiry = int(token[4:])
                except ValueError:
                    pass

        if id_parsed != node_id or role_parsed != role:
            print("ZT-CERT: Identity mismatch")
            return False

        if expiry is not None and int(time.time()) > expiry:
            print("ZT-CERT: Certificate expired")
            return False

        return True

    # ------------------------------------------------------------------
    # Micro-segmentation
    # ------------------------------------------------------------------

    def add_role_policy_rule(self, rule: RolePolicyRule) -> None:
        """Append a micro-segmentation rule and bump the policy version."""
        self._rules.append(rule)
        self._policy_version += 1
        print(f"[POLICY] Rule Added. Version: {self._policy_version}")

    def _is_within_time(self, start_hour: int, end_hour: int) -> bool:
        """Return ``True`` if the current local hour falls in [start_hour, end_hour)."""
        current_hour = time.localtime().tm_hour
        return start_hour <= current_hour < end_hour

    def _get_behavior_state(self, node_id: int, window_seconds: int) -> int:
        """
        Count transfers for *node_id* within the sliding *window_seconds* window.

        Expired entries are pruned from the history before counting.
        """
        now = time.time()
        history = self._transfer_history.setdefault(node_id, [])
        # Prune expired entries
        self._transfer_history[node_id] = [
            t for t in history if now - t <= window_seconds
        ]
        return len(self._transfer_history[node_id])

    def evaluate_micro_segmentation(
        self,
        src_node_id: int,
        dst_node_id: int,
        action: str,
    ) -> bool:
        """
        Evaluate whether the *action* between src and dst is permitted.

        Parameters
        ----------
        src_node_id : int
            Source node ID.
        dst_node_id : int
            Destination node ID.
        action : str
            Action string (e.g. "STREAM", "TRANSFER", "UPDATE").

        Returns
        -------
        bool
            ``True`` if the action is ALLOWED by policy.
        """
        registry = IdentityRegistry.get_instance()

        hs = registry.get_identity_hash(src_node_id)
        hd = registry.get_identity_hash(dst_node_id)
        src_role = registry.get_role(src_node_id)
        dst_role = registry.get_role(dst_node_id)

        current_hour = time.localtime().tm_hour
        now = time.time()

        for rule in self._rules:
            if (
                rule.src_role == src_role
                and rule.dst_role == dst_role
                and (rule.action == action or rule.action == "*")
            ):
                if not self._is_within_time(rule.start_hour, rule.end_hour):
                    continue

                transfer_count = self._get_behavior_state(
                    src_node_id, rule.window_seconds
                )
                behavior_state = 0 if transfer_count <= rule.max_transfers else 1

                # Compute integrity fingerprint Ψ
                s = (
                    hs
                    + hd
                    + action
                    + str(current_hour)
                    + rule.src_role
                    + rule.dst_role
                    + str(behavior_state)
                )
                psi = compute_sha256(s)
                print(f"[MICRO-SEG] Ψ: {psi}")

                if behavior_state == 0 and rule.effect == RuleEffect.ALLOW:
                    if action in ("TRANSFER", "WITHDRAW"):
                        self._transfer_history.setdefault(src_node_id, []).append(now)
                    return True

                if rule.effect == RuleEffect.DENY:
                    return False

        print("[MICRO-SEG] Default DENY (Least Privilege)")
        return False

    # ------------------------------------------------------------------
    # Policy integrity
    # ------------------------------------------------------------------

    def get_policy_version(self) -> int:
        """Return the current policy version counter."""
        return self._policy_version

    def get_policy_integrity_hash(self) -> str:
        """Return SHA-256 hash of the serialised policy rules (version + rules)."""
        parts = [str(self._policy_version)]
        for rule in self._rules:
            parts.extend([
                rule.src_role,
                rule.dst_role,
                rule.action,
                str(rule.start_hour),
                str(rule.end_hour),
                str(rule.window_seconds),
                str(rule.max_transfers),
                str(int(rule.effect)),
            ])
        return compute_sha256("".join(parts))
