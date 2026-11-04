"""Pure Python SHA-256, independently written from FIPS 180-4 sections 4-6.

Constants and round definitions: FIPS 180-4 sections 4.2.2, 5.3.3, 6.2.2;
also RFC 6234. No hashlib call is used by this implementation.
The continuation interface accepts an explicit state and byte counter.
"""

import struct

from .padding import MAX_MESSAGE_BYTES, sha256_padding

_MASK = 0xFFFFFFFF
_INITIAL_STATE = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)
_ROUND_CONSTANTS = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)


def _rotr32(word: int, count: int) -> int:
    """Internal rotation for a uint32 word and count in 1..31."""
    return ((word >> count) | (word << (32 - count))) & _MASK


def _compress(state: tuple, block: bytes) -> tuple:
    """Compress one 64-byte block; caller supplies a valid eight-word state."""
    schedule = list(struct.unpack(">16I", block))
    for t in range(16, 64):
        x, y = schedule[t - 15], schedule[t - 2]
        small0 = _rotr32(x, 7) ^ _rotr32(x, 18) ^ (x >> 3)
        small1 = _rotr32(y, 17) ^ _rotr32(y, 19) ^ (y >> 10)
        schedule.append((schedule[t - 16] + small0 + schedule[t - 7] + small1) & _MASK)

    a, b, c, d, e, f, g, h = state
    for constant, word in zip(_ROUND_CONSTANTS, schedule):
        big1 = _rotr32(e, 6) ^ _rotr32(e, 11) ^ _rotr32(e, 25)
        choose = (e & f) ^ ((~e & _MASK) & g)
        temp1 = (h + big1 + choose + constant + word) & _MASK
        big0 = _rotr32(a, 2) ^ _rotr32(a, 13) ^ _rotr32(a, 22)
        majority = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (big0 + majority) & _MASK
        a, b, c, d, e, f, g, h = (
            (temp1 + temp2) & _MASK, a, b, c, (d + temp1) & _MASK, e, f, g
        )
    return tuple((old + new) & _MASK for old, new in zip(state, (a, b, c, d, e, f, g, h)))


def sha256_digest(message: bytes) -> bytes:
    """Return a full 32-byte digest; accept only built-in bytes.

    TypeError: wrong input type (including bytes subclasses).
    ValueError: input length >= 2**61 bytes.
    """
    if type(message) is not bytes:
        raise TypeError("message must be built-in bytes")
    length = len(message)
    if length >= MAX_MESSAGE_BYTES:
        raise ValueError("message must be shorter than 2**61 bytes")
    state = _INITIAL_STATE
    full_end = length - length % 64
    for offset in range(0, full_end, 64):
        state = _compress(state, message[offset:offset + 64])
    # Only copy the last partial block plus padding, not the entire message.
    tail = message[full_end:] + sha256_padding(length)
    for offset in range(0, len(tail), 64):
        state = _compress(state, tail[offset:offset + 64])
    return struct.pack(">8I", *state)


def sha256_continue(data: bytes, *, state: tuple, processed_bytes: int) -> bytes:
    """Resume after complete blocks; processed_bytes includes old glue padding.

    State is eight built-in uint32 ints. The logical pre-padding length must
    remain below 2**61 bytes. This function cannot authenticate the supplied
    state or determine which earlier bytes produced it.
    """
    if type(data) is not bytes or type(state) is not tuple or type(processed_bytes) is not int:
        raise TypeError("Expected bytes, tuple and built-in int")
    if any(type(word) is not int for word in state):
        raise TypeError("State words must be built-in ints")
    if len(state) != 8 or any(not 0 <= word <= _MASK for word in state):
        raise ValueError("State must contain eight uint32 words")
    if processed_bytes < 0 or processed_bytes % 64:
        raise ValueError("processed_bytes must be nonnegative and a multiple of 64")
    total = processed_bytes + len(data)
    if total >= MAX_MESSAGE_BYTES:
        raise ValueError("Logical message must be shorter than 2**61 bytes")
    full_end = len(data) - len(data) % 64
    for offset in range(0, full_end, 64):
        state = _compress(state, data[offset:offset + 64])
    tail = data[full_end:] + sha256_padding(total)
    for offset in range(0, len(tail), 64):
        state = _compress(state, tail[offset:offset + 64])
    return struct.pack(">8I", *state)
