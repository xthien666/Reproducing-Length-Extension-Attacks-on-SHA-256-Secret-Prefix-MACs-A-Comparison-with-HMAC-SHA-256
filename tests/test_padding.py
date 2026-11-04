import unittest

from src.padding import sha256_padding


class PaddingTests(unittest.TestCase):
    def test_explicit_boundary_lengths(self):
        for length, expected in [(0, 64), (1, 63), (55, 9), (56, 72),
                                 (63, 65), (64, 64), (65, 63), (119, 9),
                                 (120, 72), (127, 65), (128, 64), (129, 63)]:
            with self.subTest(length=length):
                padding = sha256_padding(length)
                self.assertEqual(len(padding), expected)

    def test_format_all_residues_and_large_lengths(self):
        lengths = list(range(256)) + [2**32, 2**40 + 55, 2**61 - 1]
        for length in lengths:
            with self.subTest(length=length):
                padding = sha256_padding(length)
                self.assertIs(type(padding), bytes)
                self.assertEqual(padding[0], 0x80)
                self.assertTrue(all(b == 0 for b in padding[1:-8]))
                self.assertEqual(int.from_bytes(padding[-8:], "big"), length * 8)
                self.assertEqual((length + len(padding)) % 64, 0)
                self.assertTrue(9 <= len(padding) <= 72)

    def test_reject_wrong_types(self):
        class IntSubclass(int):
            pass
        for value in [True, False, 1.0, "1", None, b"1", IntSubclass(1)]:
            with self.subTest(value=value):
                with self.assertRaises(TypeError):
                    sha256_padding(value)

    def test_reject_out_of_range(self):
        for value in [-1, -64, 2**61, 2**61 + 1]:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    sha256_padding(value)


if __name__ == "__main__":
    unittest.main()
