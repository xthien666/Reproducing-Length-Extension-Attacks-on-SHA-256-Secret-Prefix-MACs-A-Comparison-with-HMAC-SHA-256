"""Public-input-only length-extension candidate generation; no verifier or I/O."""

import struct

from .padding import MAX_MESSAGE_BYTES, sha256_padding
from .sha256_core import sha256_continue


def forge_candidate(message: bytes, original_tag: bytes, append_data: bytes,
                    guessed_key_len: int) -> tuple[bytes, bytes]:
    """Return (forged_message, forged_tag), without knowing whether it verifies.

    ell=0 is supported for empty-prefix unit tests; the main grid uses 1..64.
    No key, true key length, live hash object, fixture or oracle is accepted.
    """
    if any(type(x) is not bytes for x in (message, original_tag, append_data)):
        raise TypeError("Message, tag and append_data must be built-in bytes")
    if type(guessed_key_len) is not int:
        raise TypeError("guessed_key_len must be a built-in int")
    if len(original_tag) != 32 or guessed_key_len < 0:
        raise ValueError("Expected a 32-byte tag and a nonnegative guessed length")
    prefix_len = guessed_key_len + len(message)
    glue = sha256_padding(prefix_len)
    processed = prefix_len + len(glue)
    if processed + len(append_data) >= MAX_MESSAGE_BYTES:
        raise ValueError("Extended logical message is too long")
    state = struct.unpack(">8I", original_tag)
    tag = sha256_continue(append_data, state=state, processed_bytes=processed)
    return message + glue + append_data, tag
