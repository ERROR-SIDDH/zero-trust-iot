"""
zt_hash_utils.py — Zero Trust IoT: SHA-256 hashing utilities.

Authors: Rahul S, Dr. Subbulakshmi T, Arun Santhosh R A
VIT Chennai, India

Mirrors: model/zt-hash-utils.h / zt-hash-utils.cc
"""

import hashlib


def compute_sha256(data: str) -> str:
    """
    Compute the SHA-256 hex-digest of a UTF-8 string.

    Parameters
    ----------
    data : str
        Input string to hash.

    Returns
    -------
    str
        Lowercase hex-encoded SHA-256 digest (64 characters).
    """
    return hashlib.sha256(data.encode("utf-8")).hexdigest()
