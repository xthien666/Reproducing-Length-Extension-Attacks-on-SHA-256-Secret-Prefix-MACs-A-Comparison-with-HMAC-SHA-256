"""Independent reference MACs and verifiers using the Python standard library."""

import hashlib
import hmac

from .padding import MAX_MESSAGE_BYTES

SCHEMES = ("prefix_sha256", "hmac_sha256")


def _validate(scheme, key, message):
    if type(scheme) is not str or type(key) is not bytes or type(message) is not bytes:
        raise TypeError("Expected scheme str and built-in bytes for key/message")
    if scheme not in SCHEMES:
        raise ValueError("Unknown MAC scheme")
    length = len(key) + len(message) if scheme == "prefix_sha256" else 64 + len(message)
    if len(key) >= MAX_MESSAGE_BYTES or length >= MAX_MESSAGE_BYTES:
        raise ValueError("SHA-256 input exceeds the byte-length domain")


def create_mac(scheme: str, key: bytes, message: bytes) -> bytes:
    """Orchestrator-side tag generation; never called by the attacker."""
    _validate(scheme, key, message)
    if scheme == "prefix_sha256":
        return hashlib.sha256(key + message).digest()
    return hmac.new(key, message, hashlib.sha256).digest()


def _verify(scheme, key, message, tag):
    # Check all types before any domain/length decision.
    if any(type(x) is not bytes for x in (key, message, tag)):
        raise TypeError("Key, message and tag must be built-in bytes")
    _validate(scheme, key, message)
    if len(tag) != 32:
        return False
    return hmac.compare_digest(create_mac(scheme, key, message), tag)


def verify_prefix(key: bytes, message: bytes, tag: bytes) -> bool:
    return _verify("prefix_sha256", key, message, tag)


def verify_hmac(key: bytes, message: bytes, tag: bytes) -> bool:
    return _verify("hmac_sha256", key, message, tag)
