"""
zt_encryption_utils.py — Zero Trust IoT: AES-CBC encryption/decryption.

Authors: Arun Santhosh R A, Dr. Subbulakshmi T
VIT Chennai, India

Mirrors: model/zt-encryption-utils.h / zt-encryption-utils.cc

Replaces Crypto++ AES-CBC with Python's `cryptography` library
(hazmat layer) using the identical prepend-IV-to-ciphertext scheme.
"""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

AES_KEY_LENGTH = 16   # 128-bit key  (Crypto++ AES::DEFAULT_KEYLENGTH)
AES_BLOCK_SIZE = 16   # 128-bit block (AES::BLOCKSIZE)


def encrypt_payload(data: str, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt *data* with AES-CBC using a random IV.

    Parameters
    ----------
    data : str
        Plaintext string to encrypt.
    key : bytes
        Raw AES key (16 bytes for 128-bit).

    Returns
    -------
    tuple[bytes, bytes]
        (ciphertext_with_iv_prepended, iv)
        The first element has the 16-byte IV prepended (mirrors C++ impl).
    """
    iv = os.urandom(AES_BLOCK_SIZE)
    padder = padding.PKCS7(AES_BLOCK_SIZE * 8).padder()
    padded = padder.update(data.encode("utf-8")) + padder.finalize()

    cipher = Cipher(
        algorithms.AES(key[:AES_KEY_LENGTH]),
        modes.CBC(iv),
        backend=default_backend(),
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return iv + ciphertext, iv


def decrypt_payload(cipher_with_iv: bytes, key: bytes) -> str:
    """
    Decrypt a payload produced by :func:`encrypt_payload`.

    Parameters
    ----------
    cipher_with_iv : bytes
        Bytes with the 16-byte IV prepended.
    key : bytes
        Raw AES key (16 bytes for 128-bit).

    Returns
    -------
    str
        Recovered plaintext string.
    """
    iv = cipher_with_iv[:AES_BLOCK_SIZE]
    actual_cipher = cipher_with_iv[AES_BLOCK_SIZE:]

    cipher = Cipher(
        algorithms.AES(key[:AES_KEY_LENGTH]),
        modes.CBC(iv),
        backend=default_backend(),
    )
    decryptor = cipher.decryptor()
    padded = decryptor.update(actual_cipher) + decryptor.finalize()

    unpadder = padding.PKCS7(AES_BLOCK_SIZE * 8).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode("utf-8")


def generate_session_key() -> bytes:
    """Generate a random 128-bit (16-byte) AES session key."""
    return os.urandom(AES_KEY_LENGTH)


def session_key_to_hex(key: bytes) -> str:
    """Encode raw key bytes as uppercase hex string (mirrors CryptoPP HexEncoder)."""
    return key.hex().upper()


def hex_to_bytes(hex_str: str) -> bytes:
    """Decode a hex string back to raw bytes."""
    return bytes.fromhex(hex_str)
