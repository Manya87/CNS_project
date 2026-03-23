"""Utility functions for AES-based file encryption/decryption."""

from __future__ import annotations

import base64
import hashlib
import secrets
from typing import Final

from Crypto.Cipher import AES

NONCE_SIZE: Final[int] = 16
TAG_SIZE: Final[int] = 16
MAGIC: Final[bytes] = b"SFV1"


def _derive_aes_key(secret_key: str) -> bytes:
    """Derive a 256-bit AES key from user-provided secret text using SHA-256."""
    if not secret_key:
        raise ValueError("Secret key cannot be empty.")
    return hashlib.sha256(secret_key.encode("utf-8")).digest()


def generate_secure_key(length: int = 32) -> str:
    """Generate a secure random key string suitable for user use/copying."""
    if length < 16:
        raise ValueError("Key length must be at least 16.")
    random_bytes = secrets.token_bytes(length)
    return base64.urlsafe_b64encode(random_bytes).decode("utf-8").rstrip("=")


def encrypt_data(data: bytes, secret_key: str) -> bytes:
    """Encrypt bytes with AES-256-GCM.

    Output format:
    MAGIC(4) + NONCE(16) + TAG(16) + CIPHERTEXT(N)
    """
    if not data:
        raise ValueError("No data provided for encryption.")

    key = _derive_aes_key(secret_key)
    nonce = secrets.token_bytes(NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return MAGIC + nonce + tag + ciphertext


def decrypt_data(encrypted_data: bytes, secret_key: str) -> bytes:
    """Decrypt bytes created by encrypt_data."""
    if not encrypted_data:
        raise ValueError("No encrypted data provided for decryption.")
    if len(encrypted_data) < len(MAGIC) + NONCE_SIZE + TAG_SIZE:
        raise ValueError("Encrypted data is invalid or corrupted.")

    if encrypted_data[: len(MAGIC)] != MAGIC:
        raise ValueError("File format not recognized for Secure File Vault.")

    start = len(MAGIC)
    nonce = encrypted_data[start : start + NONCE_SIZE]
    tag = encrypted_data[start + NONCE_SIZE : start + NONCE_SIZE + TAG_SIZE]
    ciphertext = encrypted_data[start + NONCE_SIZE + TAG_SIZE :]

    key = _derive_aes_key(secret_key)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        raise ValueError("Decryption failed. Check your secret key or file integrity.") from exc
