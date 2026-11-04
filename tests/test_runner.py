from copy import deepcopy
import csv
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from src.runner import (ROOT, load_config, generate_fixtures, load_fixtures,
                        validate_fixtures, run_experiment, audit_results, read_csv)
from src.experiment import ATTEMPT_FIELDS

CONFIG = ROOT / 'config/experiment.json'


class RunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.workspace = Path(cls.temp.name)
        cls.config, _ = load_config(CONFIG, 'pilot')
        cls.target = run_experiment(CONFIG, 'pilot', 'test-pilot', project_root=cls.workspace)
        cls.fixture_path = cls.workspace / 'data/test-pilot/fixtures.json'
        cls.cases = load_fixtures(cls.fixture_path, cls.config, 'pilot')

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_full_pilot_and_replay(self):
        report, summary = audit_results(self.target, self.config, 'pilot', self.cases, 'test-pilot')
        self.assertEqual((report['attempt_rows'], report['sanity_rows']), (8192, 640))
        self.assertEqual(report['accepted_by_scheme'], {'prefix_sha256': 64, 'hmac_sha256': 0})
        self.assertEqual(len(summary), 128)
        replay = run_experiment(CONFIG, 'pilot', 'test-replay', self.fixture_path, self.workspace)
        for name in ('attempts.csv', 'sanity_checks.csv', 'summary.csv'):
            def normalized(path):
                with path.open(encoding='utf-8', newline='') as stream:
                    return [{k: v for k, v in row.items() if k != 'run_id'} for row in csv.DictReader(stream)]
            self.assertEqual(normalized(self.target / name), normalized(replay / name))
        metadata = json.loads((replay / 'run_metadata.json').read_text())
        self.assertTrue(metadata['fixture_reused'])
        self.assertEqual(metadata['attacker_compression_blocks_derived_from_rows'], 12288)

    def test_fixture_schema_grid_and_public_boundary(self):
        private = json.loads(self.fixture_path.read_text())
        public = json.loads(self.fixture_path.with_name('public_cases.json').read_text())
        self.assertEqual(len(private['cases']), 64)
        self.assertTrue(all(set(c) == {'case_id', 'message_hex', 'append_id', 'append_hex', 'tags_by_scheme'} for c in public))
        for mutation in ('duplicate', 'invalid_hex', 'wrong_payload', 'key_leak', 'wrong_tag'):
            a, b = deepcopy(private), deepcopy(public)
            if mutation == 'duplicate': a['cases'][1] = a['cases'][0]
            elif mutation == 'invalid_hex': a['cases'][0]['key_hex'] = 'xx'
            elif mutation == 'wrong_payload': a['cases'][0]['append_hex'] = '00'
            elif mutation == 'key_leak': b[0]['key_hex'] = a['cases'][0]['key_hex']
            else: b[0]['tags_by_scheme']['hmac_sha256'] = '00' * 32
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                validate_fixtures(self.config, 'pilot', a, b)

    def test_audit_rejects_corrupted_records(self):
        for mutation in ('missing', 'duplicate', 'acceptance', 'label', 'bool', 'sanity'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as folder:
                target = Path(folder) / 'copy'
                shutil.copytree(self.target, target)
                path = target / ('sanity_checks.csv' if mutation == 'sanity' else 'attempts.csv')
                with path.open(encoding='utf-8', newline='') as stream:
                    reader = csv.DictReader(stream)
                    fields, rows = reader.fieldnames, list(reader)
                if mutation == 'missing': rows.pop()
                elif mutation == 'duplicate': rows[1] = rows[0]
                elif mutation == 'acceptance': rows[0]['accepted'] = 'False' if rows[0]['accepted'] == 'True' else 'True'
                elif mutation == 'label': rows[0]['actual_key_len_bytes'] = '999'
                elif mutation == 'bool': rows[0]['accepted'] = '0'
                else: rows[1] = rows[0]
                with path.open('w', encoding='utf-8', newline='') as stream:
                    writer = csv.DictWriter(stream, fieldnames=fields)
                    writer.writeheader()
                    writer.writerows(rows)
                with self.assertRaises(ValueError):
                    audit_results(target, self.config, 'pilot', self.cases, 'test-pilot')

    def test_reject_existing_output_and_invalid_id(self):
        original = (self.target / 'run_metadata.json').read_bytes()
        with self.assertRaises(FileExistsError):
            run_experiment(CONFIG, 'pilot', 'test-pilot', self.fixture_path, self.workspace)
        self.assertEqual((self.target / 'run_metadata.json').read_bytes(), original)
        for name in ('../escape', 'bad/name', ''):
            with self.assertRaises(ValueError):
                run_experiment(CONFIG, 'pilot', name, project_root=self.workspace)
        with self.assertRaises(FileExistsError):
            generate_fixtures(self.config, 'pilot', 'test-pilot', self.workspace / 'data')

    def test_failed_run_retains_partial_evidence(self):
        from src.experiment import scan_case
        counter = 0
        def fail_second(*args, **kwargs):
            nonlocal counter
            counter += 1
            if counter == 2:
                raise RuntimeError('injected interruption after one completed case')
            return scan_case(*args, **kwargs)
        with patch('src.runner.scan_case', side_effect=fail_second), self.assertRaises(RuntimeError):
            run_experiment(CONFIG, 'pilot', 'test-failure', self.fixture_path, self.workspace)
        target = self.workspace / 'results/test-failure'
        metadata = json.loads((target / 'run_metadata.json').read_text())
        self.assertEqual(metadata['completion_status'], 'failed')
        self.assertEqual(metadata['completed_case_count'], 1)
        self.assertEqual(len(read_csv(target / 'attempts.csv', ATTEMPT_FIELDS)), 128)

    def test_profile_mismatch_and_unsupported_e5(self):
        with self.assertRaises(ValueError):
            load_fixtures(self.fixture_path, self.config, 'main')
        config = deepcopy(self.config)
        config['extra_experiment']['enabled'] = True
        path = self.workspace / 'e5.json'
        path.write_text(json.dumps(config))
        with self.assertRaises(ValueError):
            load_config(path, 'pilot')
