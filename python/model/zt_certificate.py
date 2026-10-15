"""
zt_certificate.py — Zero Trust IoT: RSA-based Certificate Authority.

Authors: Arun Santhosh R A, Dr. Subbulakshmi T
VIT Chennai, India

Mirrors: model/zt-certificate.h / zt-certificate.cc

Replaces Crypto++ RSA/PSSR/SHA1 with Python's `cryptography` library
(RSA-PSS with SHA-1, 1024-bit keys — matching the C++ parameters).
"""

import time
import base64
from typing import Optional
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


class CertificateAuthority:
    """
    Simulates a Certificate Authority (CA) that issues and signs
    identity certificates using RSA-PSS / SHA-1 (1024-bit).

    Mirrors the C++ ``CertificateAuthority`` class.
    """

    def __init__(self) -> None:
        """Generate RSA-1024 key pair on construction (matches C++ ctor)."""
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=1024,
            backend=default_backend(),
        )
        self._public_key = self._private_key.public_key()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def sign_identity(self, node_id: int, role: str, expiry: int) -> str:
        """
        Issue and sign a certificate for a node.

        Parameters
        ----------
        node_id : int
            Unique node identifier.
        role : str
            Role assigned to the node (e.g. "sensor", "gateway").
        expiry : int
            Unix timestamp representing certificate expiry.

        Returns
        -------
        str
            Certificate string:
            ``ID:<id>|ROLE:<role>|EXP:<expiry>|SIG:<base64_signature>``
        """
        content = f"ID:{node_id}|ROLE:{role}|EXP:{expiry}"
        content_bytes = content.encode("utf-8")

        signature = self._private_key.sign(
            content_bytes,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA1()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA1(),
        )
        encoded_sig = base64.b64encode(signature).decode("ascii")
        return f"{content}|SIG:{encoded_sig}"

    def get_public_key(self):
        """Return the CA's RSA public key object."""
        return self._public_key


# ---------------------------------------------------------------------------


class ZtPolicyEngineWithCert:
    """
    Zero Trust policy engine that enforces access control using RSA certificates.

    Mirrors the C++ ``ZtPolicyEngineWithCert`` class.
    """

    def __init__(self) -> None:
        self._ca_public_key = None
        self._revoked: set[int] = set()

    def set_ca_public_key(self, public_key) -> None:
        """Set the CA public key used for certificate verification."""
        self._ca_public_key = public_key

    def revoke(self, node_id: int) -> None:
        """Revoke a node so it can never be authorised again."""
        self._revoked.add(node_id)

    def authorize(self, node_id: int, role: str, cert_str: str) -> bool:
        """
        Verify certificate signature, check revocation, ID/role match, and expiry.

        Parameters
        ----------
        node_id : int
            Node's claimed ID.
        role : str
            Node's claimed role.
        cert_str : str
            Certificate string produced by :meth:`CertificateAuthority.sign_identity`.

        Returns
        -------
        bool
            ``True`` if all checks pass.
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

        # Parse fields
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
