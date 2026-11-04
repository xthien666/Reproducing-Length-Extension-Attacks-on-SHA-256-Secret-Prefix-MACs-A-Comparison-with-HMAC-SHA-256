import csv
import hashlib
import hmac
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.attacker import forge_candidate
from src.experiment import ATTEMPT_FIELDS, SANITY_FIELDS, scan_case, write_case_results
from src.macs import create_mac, verify_prefix, verify_hmac


class MacTests(unittest.TestCase):
    def test_rfc4231_full_length_vectors(self):
        # Official RFC 4231 sections 4.2, 4.3, 4.4 and 4.7; SHA-256 columns.
        vectors = (
            (bytes.fromhex('0b') * 20, b'Hi There', 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'),
            (b'Jefe', b'what do ya want for nothing?', '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843'),
            (bytes.fromhex('aa') * 20, bytes.fromhex('dd') * 50, '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe'),
            (bytes.fromhex('aa') * 131, b'Test Using Larger Than Block-Size Key - Hash Key First', '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54'),
        )
        for key, message, expected in vectors:
            with self.subTest(key_len=len(key)):
                self.assertEqual(create_mac('hmac_sha256', key, message).hex(), expected)
                self.assertTrue(verify_hmac(key, message, bytes.fromhex(expected)))

    def test_key_boundaries_and_verifier_negatives(self):
        for n in (0, 1, 32, 64, 65, 131):
            key, message = bytes(range(n)), b'message'
            for scheme, verifier, expected in (
                ('prefix_sha256', verify_prefix, hashlib.sha256(key + message).digest()),
                ('hmac_sha256', verify_hmac, hmac.new(key, message, hashlib.sha256).digest()),
            ):
                with self.subTest(n=n, scheme=scheme):
                    self.assertEqual(create_mac(scheme, key, message), expected)
                    self.assertTrue(verifier(key, message, expected))
                    self.assertFalse(verifier(key, message + b'!', expected))
                    for invalid in (b'', expected[:-1], expected + b'0', bytes(32)):
                        self.assertFalse(verifier(key, message, invalid))

    def test_strict_types(self):
        for verifier in (verify_prefix, verify_hmac):
            for args in ((bytearray(), b'', b''), (b'', '', b''), (b'', b'', bytearray(32))):
                with self.assertRaises(TypeError):
                    verifier(*args)
        with self.assertRaises(ValueError):
            create_mac('unknown', b'', b'')


class ExperimentTests(unittest.TestCase):
    def setUp(self):
        self.key, self.message, self.suffix = bytes(range(16)), bytes(range(32)), b';role=admin'

    def scan(self, **kwargs):
        return scan_case('test-run', 'case-001', self.key, self.message, self.suffix, 'role_admin', **kwargs)

    def test_paired_exhaustive_scan_and_public_call_boundary(self):
        with patch('src.experiment.forge_candidate', wraps=forge_candidate) as spy:
            rows, checks = self.scan()
        self.assertEqual(len(rows), 128)
        self.assertEqual(len(checks), 10)
        self.assertTrue(all(r['passed'] for r in checks))
        self.assertEqual([(r['scheme'], r['guessed_key_len_bytes']) for r in rows if r['accepted']], [('prefix_sha256', 16)])
        self.assertEqual(spy.call_count, 128)
        for call, row in zip(spy.call_args_list, rows):
            self.assertEqual(call.args, (self.message, bytes.fromhex(row['original_tag_hex']), self.suffix, row['guessed_key_len_bytes']))
            self.assertEqual(call.kwargs, {})
        for scheme in ('prefix_sha256', 'hmac_sha256'):
            subset = [r for r in rows if r['scheme'] == scheme]
            self.assertEqual([r['guessed_key_len_bytes'] for r in subset], list(range(1, 65)))
            self.assertEqual(subset[0]['original_tag_hex'], create_mac(scheme, self.key, self.message).hex())
        self.assertNotEqual(rows[0]['original_tag_hex'], rows[64]['original_tag_hex'])

    def test_csv_separation_roundtrip_and_no_overwrite(self):
        rows, checks = self.scan(guesses=(15, 16, 17))
        with tempfile.TemporaryDirectory() as folder:
            target = write_case_results(folder, 'test-run', rows, checks)
            for filename, fields, expected in (('attempts.csv', ATTEMPT_FIELDS, rows), ('sanity_checks.csv', SANITY_FIELDS, checks), ('extra_attempts.csv', ATTEMPT_FIELDS, [])):
                with (target / filename).open(encoding='utf-8', newline='') as stream:
                    reader = csv.DictReader(stream)
                    self.assertEqual(reader.fieldnames, list(fields))
                    self.assertEqual(list(reader), [{k: str(v) for k, v in r.items()} for r in expected])
            self.assertNotIn('guessed_key_len_bytes', SANITY_FIELDS)
            with self.assertRaises(FileExistsError):
                write_case_results(folder, 'test-run', rows, checks)

    def test_invalid_runs_and_duplicate_rows(self):
        rows, checks = self.scan(guesses=(16,))
        with tempfile.TemporaryDirectory() as folder:
            for run_id, attempts, controls in (
                ('../escape', rows, checks), ('different', rows, checks),
                ('test-run', rows + rows, checks), ('test-run', rows, checks + checks),
                ('test-run', [dict(rows[0], extra='wrong')], checks),
            ):
                with self.assertRaises(ValueError):
                    write_case_results(folder, run_id, attempts, controls)
            self.assertEqual(list(Path(folder).iterdir()), [])

    def test_invalid_guess_grid(self):
        for guesses in ((), (0,), (-1,), (2, 1), (1, 1)):
            with self.assertRaises(ValueError):
                self.scan(guesses=guesses)
        with self.assertRaises(TypeError):
            self.scan(guesses=(True,))

    def test_csv_types_and_hex(self):
        rows, checks = self.scan(guesses=(16,))
        with tempfile.TemporaryDirectory() as folder:
            for field, value, error in (
                ('accepted', 'False', TypeError), ('guessed_key_len_bytes', True, TypeError),
                ('forged_tag_hex', '00', ValueError), ('scheme', 'unknown', ValueError),
            ):
                with self.subTest(field=field), self.assertRaises(error):
                    write_case_results(folder, 'test-run', [dict(rows[0], **{field: value})], checks)

    def test_demo_artifacts_match_verifiers(self):
        from main import demo
        with tempfile.TemporaryDirectory() as folder:
            target = demo('test-demo', folder)
            metadata = json.loads((target / 'run_metadata.json').read_text())
            self.assertEqual(metadata['status'], 'completed')
            self.assertEqual(metadata['accepted_guesses'], {'prefix_sha256': [16], 'hmac_sha256': []})
            for name, digest in metadata['artifact_sha256'].items():
                self.assertEqual(hashlib.sha256((target / name).read_bytes()).hexdigest(), digest)
            examples = json.loads((target / 'demo.json').read_text())['examples']
            self.assertEqual(len(examples), 6)
            for row in examples:
                verifier = verify_prefix if row['scheme'] == 'prefix_sha256' else verify_hmac
                msg, tag = bytes.fromhex(row['forged_message_hex']), bytes.fromhex(row['forged_tag_hex'])
                self.assertEqual(verifier(self.key, msg, tag), row['accepted'])
                self.assertEqual(msg, self.message + bytes.fromhex(row['glue_padding_hex']) + self.suffix)
