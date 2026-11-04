import hashlib
import struct
import unittest

from src.attacker import forge_candidate
from src.macs import create_mac, verify_prefix, verify_hmac
from src.padding import MAX_MESSAGE_BYTES, sha256_padding
from src.sha256_core import sha256_continue


class ContinuationTests(unittest.TestCase):
    def test_against_full_hash_at_boundaries(self):
        for n in (0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 1024):
            original = bytes(i % 256 for i in range(n))
            state = struct.unpack('>8I', hashlib.sha256(original).digest())
            glue = sha256_padding(n)
            for size in (0, 1, 55, 56, 63, 64, 80, 129):
                suffix = bytes(i % 256 for i in range(size))
                with self.subTest(n=n, size=size):
                    self.assertEqual(sha256_continue(suffix, state=state, processed_bytes=n + len(glue)),
                                     hashlib.sha256(original + glue + suffix).digest())

    def test_initial_state_zero_counter(self):
        state = (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)
        self.assertEqual(sha256_continue(b'abc', state=state, processed_bytes=0), hashlib.sha256(b'abc').digest())

    def test_invalid_inputs(self):
        state = (0,) * 8
        for data, s, count, error in (
            (bytearray(), state, 0, TypeError), (b'', list(state), 0, TypeError),
            (b'', state, True, TypeError), (b'', (True,) + state[1:], 0, TypeError),
            (b'', (0,) * 7, 0, ValueError), (b'', (-1,) + state[1:], 0, ValueError),
            (b'', (2**32,) + state[1:], 0, ValueError),
            (b'', state, -64, ValueError), (b'', state, 1, ValueError),
            (b'', state, MAX_MESSAGE_BYTES, ValueError),
            (bytes(64), state, MAX_MESSAGE_BYTES - 64, ValueError),
        ):
            with self.subTest(data=data, state=s, count=count), self.assertRaises(error):
                sha256_continue(data, state=s, processed_bytes=count)
        with self.assertRaises(TypeError):
            sha256_continue(b'', state, 0)


class AttackTests(unittest.TestCase):
    def test_correct_guesses_across_padding_boundaries(self):
        for key_len in (0, 8, 16, 32, 48):
            key = bytes(range(key_len))
            for total in (55, 56, 63, 64, 119, 120, 127, 128):
                message = bytes(range(total - key_len))
                for suffix in (b';role=admin', bytes(range(80))):
                    with self.subTest(key_len=key_len, total=total, size=len(suffix)):
                        tag = hashlib.sha256(key + message).digest()
                        forged, candidate = forge_candidate(message, tag, suffix, key_len)
                        self.assertNotEqual(forged, message)
                        self.assertTrue(verify_prefix(key, forged, candidate))

    def test_same_candidate_tag_does_not_imply_acceptance(self):
        key, message, suffix = bytes(range(16)), bytes(range(32)), b';role=admin'
        tag = hashlib.sha256(key + message).digest()
        pairs = [forge_candidate(message, tag, suffix, guess) for guess in (15, 16, 17)]
        self.assertEqual(len({p[1] for p in pairs}), 1)
        self.assertEqual(len({p[0] for p in pairs}), 3)
        self.assertEqual([verify_prefix(key, *p) for p in pairs], [False, True, False])

    def test_hmac_own_original_tag(self):
        key, message, suffix = bytes(range(16)), bytes(range(32)), b';role=admin'
        tag = create_mac('hmac_sha256', key, message)
        self.assertTrue(verify_hmac(key, message, tag))
        for guess in range(1, 65):
            with self.subTest(guess=guess):
                self.assertFalse(verify_hmac(key, *forge_candidate(message, tag, suffix, guess)))

    def test_empty_message_and_suffix(self):
        for key in (b'', b'key'):
            pair = forge_candidate(b'', hashlib.sha256(key).digest(), b'', len(key))
            self.assertTrue(verify_prefix(key, *pair))

    def test_invalid_public_arguments(self):
        tag = bytes(32)
        for args, error in (
            ((b'M', tag, b'X', -1), ValueError), ((b'M', tag, b'X', True), TypeError),
            ((b'M', tag[:-1], b'X', 1), ValueError), ((b'M', tag + b'0', b'X', 1), ValueError),
            ((bytearray(b'M'), tag, b'X', 1), TypeError), ((b'M', tag, 'X', 1), TypeError),
            ((b'', tag, b'', MAX_MESSAGE_BYTES), ValueError),
            ((b'', tag, b'', MAX_MESSAGE_BYTES - 1), ValueError),
        ):
            with self.subTest(args=args), self.assertRaises(error):
                forge_candidate(*args)
