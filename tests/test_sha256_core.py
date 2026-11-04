import hashlib
import random
import unittest

from src.sha256_core import _rotr32, sha256_digest


class SHA256Tests(unittest.TestCase):
    def assert_matches_reference(self, data):
        before = data
        digest = sha256_digest(data)
        self.assertIs(type(digest), bytes)
        self.assertEqual(len(digest), 32)
        self.assertEqual(digest, hashlib.sha256(data).digest())
        self.assertEqual(data, before)

    def test_fixed_known_answers(self):
        vectors = [
            (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
             "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
        ]
        for data, expected in vectors:
            with self.subTest(length=len(data)):
                self.assertEqual(sha256_digest(data).hex(), expected)
                self.assert_matches_reference(data)

    def test_required_boundaries_ascii_and_binary(self):
        for length in [0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129]:
            for kind, data in [
                ("ascii", b"A" * length),
                ("binary", bytes((i * 73 + 128) % 256 for i in range(length))),
            ]:
                with self.subTest(length=length, kind=kind):
                    self.assert_matches_reference(data)

    def test_all_small_lengths_seeded_bytes(self):
        rng = random.Random(20261104)  # Test data only, never experiment keys.
        for length in range(257):
            with self.subTest(length=length):
                self.assert_matches_reference(rng.randbytes(length))

    def test_multiblock_messages(self):
        for data in [bytes(range(256)) * 16, b"\x00" * 8192,
                     b"\xff" * 10000, b"a" * 1000000]:
            with self.subTest(length=len(data), first=data[0]):
                self.assert_matches_reference(data)

    def test_repeated_calls_are_independent(self):
        for data in [b"abc", bytes(range(256)), b"", b"abc"]:
            self.assert_matches_reference(data)

    def test_rotation_known_answers(self):
        for word, count, expected in [
            (1, 1, 0x80000000), (0x80000000, 31, 1),
            (0x12345678, 4, 0x81234567), (0xFFFFFFFF, 7, 0xFFFFFFFF), (0, 13, 0),
        ]:
            with self.subTest(word=word, count=count):
                self.assertEqual(_rotr32(word, count), expected)

    def test_reject_wrong_types(self):
        class BytesSubclass(bytes):
            pass
        for data in ["abc", bytearray(b"abc"), memoryview(b"abc"), None,
                     3, True, [1, 2, 3], BytesSubclass(b"abc")]:
            with self.subTest(type=type(data).__name__):
                with self.assertRaises(TypeError):
                    sha256_digest(data)


if __name__ == "__main__":
    unittest.main()
