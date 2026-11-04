"""Byte-aligned SHA-256 padding, per FIPS 180-4 section 5.1.1."""

MAX_MESSAGE_BYTES = 1 << 61


def sha256_padding(message_len_bytes: int) -> bytes:
    """Return padding only; reject bool and lengths outside [0, 2**61)."""
    if type(message_len_bytes) is not int:
        raise TypeError("message_len_bytes must be a built-in int")
    if not 0 <= message_len_bytes < MAX_MESSAGE_BYTES:
        raise ValueError("message_len_bytes must be in [0, 2**61)")
    zeros = (55 - message_len_bytes) % 64
    return b"\x80" + b"\x00" * zeros + (8 * message_len_bytes).to_bytes(8, "big")
