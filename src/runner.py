"""Persist random fixtures, execute configured grids, and audit saved CSV data."""

from collections import Counter
import csv
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import platform
import re
import secrets
import ssl
import time

from scripts.check_config import validate_config
from .experiment import ATTEMPT_FIELDS, SANITY_FIELDS, scan_case, _validate_rows
from .macs import create_mac, SCHEMES

ROOT = Path(__file__).resolve().parents[1]
SUMMARY_FIELDS = ('run_id', 'case_id', 'scheme', 'attempts', 'accepted_candidates',
                  'accepted_at_true_length', 'first_accepted_attempt', 'sanity_passed')
BOOL_FIELDS = {'accepted', 'expected_accept', 'actual_accept', 'passed'}
INT_FIELDS = {'repetition_id', 'actual_key_len_bytes', 'message_len_bytes',
              'original_total_len_bytes', 'append_len_bytes', 'guessed_key_len_bytes',
              'glue_padding_len_bytes', 'processed_bytes', 'forged_message_len_bytes', 'attempt_index'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def identifier(value):
    require(type(value) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]*', value), 'Invalid run_id')
    return value


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def load_config(path, profile):
    config = json.loads(Path(path).read_text(encoding='utf-8'))
    counts = validate_config(config)
    require(profile in counts, 'Unknown profile')
    require(config['extra_experiment']['enabled'] is False, 'E5 is not implemented by this runner')
    return config, counts[profile]


def grid_combinations(config, profile):
    grid = config['grid']
    return [(k, total, payload['id'], repetition)
            for k in grid['key_lengths_bytes'] for total in grid['original_total_lengths_bytes']
            for payload in grid['append_payloads']
            for repetition in range(config['profiles'][profile]['repetitions_per_combination'])]


def public_case(case):
    key, message = bytes.fromhex(case['key_hex']), bytes.fromhex(case['message_hex'])
    return {name: case[name] for name in ('case_id', 'message_hex', 'append_id', 'append_hex')} | {
        'tags_by_scheme': {scheme: create_mac(scheme, key, message).hex() for scheme in SCHEMES}}


def generate_fixtures(config, profile, run_id, data_root):
    identifier(run_id)
    payloads = {p['id']: p['data'] for p in config['grid']['append_payloads']}
    cases = []
    for key_len, total, append_id, repetition in grid_combinations(config, profile):
        cases.append({'case_id': 'case-' + secrets.token_hex(12),
                      'key_hex': secrets.token_bytes(key_len).hex(),
                      'message_hex': secrets.token_bytes(total - key_len).hex(),
                      'append_id': append_id, 'append_hex': payloads[append_id],
                      'repetition_id': repetition})
    secrets.SystemRandom().shuffle(cases)
    private = {'schema_version': 1, 'fixture_run_id': run_id, 'profile': profile, 'cases': cases}
    public = [public_case(case) for case in cases]
    validate_fixtures(config, profile, private, public)
    target = Path(data_root) / run_id
    target.mkdir(parents=True, exist_ok=False)
    save_json(target / 'fixtures.json', private)
    save_json(target / 'public_cases.json', public)
    return target / 'fixtures.json'


def decode_hex(value):
    require(type(value) is str and re.fullmatch(r'(?:[0-9a-f]{2})+', value), 'Invalid fixture hex')
    return bytes.fromhex(value)


def validate_fixtures(config, profile, private, public):
    require(set(private) == {'schema_version', 'fixture_run_id', 'profile', 'cases'}, 'Private envelope fields mismatch')
    require(type(private['schema_version']) is int and private['schema_version'] == 1, 'Fixture schema mismatch')
    require(private['profile'] == profile, 'Fixture profile mismatch')
    identifier(private['fixture_run_id'])
    cases = private['cases']
    require(type(cases) is list and type(public) is list, 'Fixture cases must be lists')
    payloads = {p['id']: p['data'] for p in config['grid']['append_payloads']}
    observed, ids = [], []
    for case in cases:
        require(set(case) == {'case_id', 'key_hex', 'message_hex', 'append_id', 'append_hex', 'repetition_id'}, 'Private case fields mismatch')
        require(type(case['case_id']) is str and re.fullmatch(r'case-[0-9a-f]{24}', case['case_id']), 'Invalid opaque case id')
        require(type(case['repetition_id']) is int, 'Invalid repetition type')
        key, message = decode_hex(case['key_hex']), decode_hex(case['message_hex'])
        decode_hex(case['append_hex'])
        require(case['append_hex'] == payloads.get(case['append_id']), 'Fixture payload mismatch')
        observed.append((len(key), len(key) + len(message), case['append_id'], case['repetition_id']))
        ids.append(case['case_id'])
    require(len(set(ids)) == len(ids), 'Duplicate case id')
    require(Counter(observed) == Counter(grid_combinations(config, profile)), 'Missing/duplicate/off-grid fixture combination')
    require(public == [public_case(case) for case in cases], 'Public cases or scheme tags differ from private fixtures')
    return cases


def load_fixtures(path, config, profile):
    path = Path(path)
    private = json.loads(path.read_text(encoding='utf-8'))
    public = json.loads(path.with_name('public_cases.json').read_text(encoding='utf-8'))
    return validate_fixtures(config, profile, private, public)


def write_csv(path, fields, rows):
    with Path(path).open('x', encoding='utf-8', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def read_csv(path, fields):
    with Path(path).open(encoding='utf-8', newline='') as stream:
        reader = csv.DictReader(stream)
        require(reader.fieldnames == list(fields), f'CSV header mismatch: {path}')
        rows = list(reader)
    for row in rows:
        require(set(row) == set(fields) and all(v is not None for v in row.values()), 'Malformed CSV row')
        for name in fields:
            if name in BOOL_FIELDS:
                require(row[name] in ('True', 'False'), f'Invalid boolean: {name}')
                row[name] = row[name] == 'True'
            elif name in INT_FIELDS:
                require(re.fullmatch(r'0|[1-9][0-9]*', row[name]), f'Invalid integer: {name}')
                row[name] = int(row[name])
    return _validate_rows(rows, fields)


def audit_results(target, config, profile, cases, run_id):
    """Read every row; rebuild padding independently and verify with hashlib/hmac.

    No custom SHA-256, attacker or experiment sanity function is used here.
    This checks recorded decisions; replay additionally checks every candidate tag.
    """
    target = Path(target)
    rows = read_csv(target / 'attempts.csv', ATTEMPT_FIELDS)
    checks = read_csv(target / 'sanity_checks.csv', SANITY_FIELDS)
    extras = read_csv(target / 'extra_attempts.csv', ATTEMPT_FIELDS)
    expected = config['profiles'][profile]['expected_counts']
    require(len(rows) == expected['candidate_attempts'] and len(checks) == expected['sanity_checks'] and not extras, 'CSV row counts mismatch')
    by_case = {c['case_id']: c for c in cases}
    require(len(by_case) == expected['base_cases'], 'Case count mismatch')
    grouped, controls = {}, {}
    for row in rows:
        require(row['run_id'] == run_id and row['case_id'] in by_case, 'Attempt run/case mismatch')
        pair = (row['case_id'], row['scheme'])
        grouped.setdefault(pair, []).append(row)
        case = by_case[row['case_id']]
        key, msg, suffix = (bytes.fromhex(case[k]) for k in ('key_hex', 'message_hex', 'append_hex'))
        guess = row['guessed_key_len_bytes']
        require(1 <= guess <= 64, 'Guess outside configured grid')
        length = guess + len(msg)
        glue = b'\x80' + bytes((55 - length) % 64) + (8 * length).to_bytes(8, 'big')
        forged = msg + glue + suffix
        scheme = row['scheme']
        reference = (lambda m: hashlib.sha256(key + m).digest()) if scheme == 'prefix_sha256' else (lambda m: hmac.new(key, m, hashlib.sha256).digest())
        derived = {'repetition_id': case['repetition_id'], 'actual_key_len_bytes': len(key),
                   'message_len_bytes': len(msg), 'original_total_len_bytes': len(key) + len(msg),
                   'append_id': case['append_id'], 'append_len_bytes': len(suffix),
                   'glue_padding_len_bytes': len(glue), 'processed_bytes': length + len(glue),
                   'forged_message_len_bytes': len(forged), 'original_tag_hex': reference(msg).hex(),
                   'attempt_index': guess}
        require(all(row[k] == v for k, v in derived.items()), 'Attempt labels/tag/lengths disagree with fixture')
        observed = hmac.compare_digest(reference(forged), bytes.fromhex(row['forged_tag_hex']))
        require(row['accepted'] == observed, 'Recorded acceptance differs from independent verifier')
        require(observed == (scheme == 'prefix_sha256' and guess == len(key)), 'Unexpected acceptance pattern; inspect retained raw data')
    for row in checks:
        require(row['run_id'] == run_id and row['case_id'] in by_case, 'Sanity run/case mismatch')
        pair = (row['case_id'], row['scheme'])
        controls.setdefault(pair, []).append(row)
        case = by_case[row['case_id']]
        key, msg, suffix = (bytes.fromhex(case[k]) for k in ('key_hex', 'message_hex', 'append_hex'))
        reference = (lambda m: hashlib.sha256(key + m).digest()) if row['scheme'] == 'prefix_sha256' else (lambda m: hmac.new(key, m, hashlib.sha256).digest())
        tag = reference(msg)
        inputs = {'original': (msg, tag), 'message_bit_flip': (bytes([msg[0] ^ 1]) + msg[1:], tag),
                  'tag_bit_flip': (msg, bytes([tag[0] ^ 1]) + tag[1:]),
                  'append_keep_tag': (msg + suffix, tag), 'short_tag': (msg, tag[:-1])}
        test_msg, test_tag = inputs[row['check_type']]
        observed = len(test_tag) == 32 and hmac.compare_digest(reference(test_msg), test_tag)
        expected_accept = row['check_type'] == 'original'
        require(row['actual_accept'] == observed and row['expected_accept'] == expected_accept
                and row['passed'] == (observed == expected_accept) and row['passed'], 'Sanity decision mismatch')
    pairs = {(c['case_id'], scheme) for c in cases for scheme in SCHEMES}
    require(set(grouped) == set(controls) == pairs, 'Missing case/scheme pair')
    summary = []
    for pair in sorted(pairs):
        group, control = grouped[pair], controls[pair]
        require([r['guessed_key_len_bytes'] for r in group] == list(range(1, 65)), 'Duplicate, missing or unordered guesses')
        require(Counter(r['check_type'] for r in control) == Counter(c['id'] for c in config['sanity_checks']), 'Duplicate or missing sanity controls')
        accepted = [r for r in group if r['accepted']]
        summary.append(dict(zip(SUMMARY_FIELDS, (run_id, pair[0], pair[1], len(group), len(accepted),
            any(r['accepted'] and r['guessed_key_len_bytes'] == r['actual_key_len_bytes'] for r in group),
            accepted[0]['attempt_index'] if accepted else 'not_found', sum(r['passed'] for r in control)))))
    report = {'status': 'passed', 'base_cases': len(cases), 'case_scheme_pairs': len(pairs),
              'attempt_rows': len(rows), 'sanity_rows': len(checks), 'extra_rows': len(extras),
              'sanity_passed': sum(r['passed'] for r in checks),
              'accepted_by_scheme': {s: sum(r['accepted'] for r in rows if r['scheme'] == s) for s in SCHEMES},
              'cases_with_acceptance': {s: sum(r['accepted_candidates'] > 0 for r in summary if r['scheme'] == s) for s in SCHEMES},
              'checks': ['exact grid coverage', 'unique ordered guesses 1..64', 'unique five sanity controls',
                         'strict CSV types and hex', 'all labels and original tags match fixtures',
                         'all recorded acceptance decisions rechecked with independent hashlib/hmac', 'expected acceptance pattern']}
    return report, summary


def run_experiment(config_path, profile, run_id, fixture_path=None, project_root=ROOT):
    start = time.perf_counter()
    identifier(run_id)
    config, counts = load_config(config_path, profile)
    project_root = Path(project_root)
    target = project_root / 'results' / run_id
    if fixture_path is None:
        require(not (project_root / 'data' / run_id).exists(), 'Fixture directory already exists; use --fixtures to reuse it')
    target.mkdir(parents=True, exist_ok=False)
    source_files = sorted((ROOT / 'src').glob('*.py')) + [ROOT / 'main.py', ROOT / 'scripts/check_config.py']
    metadata = {'run_id': run_id, 'run_kind': profile, 'completion_status': 'running',
                'timestamp_with_timezone': datetime.now(timezone.utc).isoformat(),
                'python_version': platform.python_version(), 'os': platform.platform(),
                'cpu': platform.processor(), 'logical_cpu_count': os.cpu_count(), 'openssl': ssl.OPENSSL_VERSION,
                'source_sha256': {p.relative_to(ROOT).as_posix(): digest(p) for p in source_files},
                'config_path': str(Path(config_path).resolve()), 'config_digest': digest(config_path),
                'planned_case_count': counts['base_cases'], 'completed_case_count': 0,
                'planned_attempt_count': counts['candidate_attempts'], 'completed_attempt_count': 0,
                'planned_sanity_count': counts['sanity_checks'], 'completed_sanity_count': 0,
                'planned_extra_attempt_count': 0, 'completed_extra_attempt_count': 0,
                'warmup': 'none', 'cache': False, 'early_stop': False, 'e5_enabled': False,
                'timing_scope': {'setup_seconds': 'config validation, initial metadata, fixture generation/loading/validation, snapshots',
                                 'scan_and_csv_seconds': 'original tags, five controls, all forgeries/verifications, row construction and three CSV writes',
                                 'audit_and_summary_seconds': 'read back all CSV, independent verification, summary and integrity report writes',
                                 'total_seconds': 'function entry through artifact hashes; excludes imports and final metadata serialization'},
                'fixture_reused': fixture_path is not None}
    save_json(target / 'run_metadata.json', metadata)
    rows, checks = [], []
    try:
        (target / 'config_snapshot.json').write_bytes(Path(config_path).read_bytes())
        if fixture_path is None:
            fixture_path = generate_fixtures(config, profile, run_id, project_root / 'data')
        fixture_path = Path(fixture_path).resolve()
        cases = load_fixtures(fixture_path, config, profile)
        metadata.update({'fixture_path': str(fixture_path), 'fixture_digest': digest(fixture_path),
                         'public_fixture_path': str(fixture_path.with_name('public_cases.json')),
                         'public_fixture_digest': digest(fixture_path.with_name('public_cases.json'))})
        scan_start = time.perf_counter()
        metadata['setup_seconds'] = scan_start - start
        for case in cases:
            key, msg, suffix = (bytes.fromhex(case[k]) for k in ('key_hex', 'message_hex', 'append_hex'))
            attempts, controls = scan_case(run_id, case['case_id'], key, msg, suffix, case['append_id'], case['repetition_id'])
            rows.extend(attempts)
            checks.extend(controls)
            metadata['completed_case_count'] += 1
            metadata['completed_attempt_count'] = len(rows)
            metadata['completed_sanity_count'] = len(checks)
        write_csv(target / 'attempts.csv', ATTEMPT_FIELDS, rows)
        write_csv(target / 'sanity_checks.csv', SANITY_FIELDS, checks)
        write_csv(target / 'extra_attempts.csv', ATTEMPT_FIELDS, [])
        metadata['scan_and_csv_seconds'] = time.perf_counter() - scan_start
        audit_start = time.perf_counter()
        integrity, summary = audit_results(target, config, profile, cases, run_id)
        write_csv(target / 'summary.csv', SUMMARY_FIELDS, summary)
        save_json(target / 'integrity.json', integrity)
        metadata['audit_and_summary_seconds'] = time.perf_counter() - audit_start
        metadata['attacker_continuation_calls_derived_from_rows'] = len(rows)
        metadata['attacker_compression_blocks_derived_from_rows'] = sum((r['append_len_bytes'] + 9 + (55 - r['append_len_bytes']) % 64) // 64 for r in rows)
        require(metadata['attacker_compression_blocks_derived_from_rows'] == counts['attacker_compression_blocks'], 'Derived block count mismatch')
        metadata['artifact_sha256'] = {p.name: digest(p) for p in sorted(target.iterdir()) if p.name != 'run_metadata.json'}
        metadata['completion_status'] = 'completed'
        metadata['total_seconds'] = time.perf_counter() - start
        save_json(target / 'run_metadata.json', metadata)
    except BaseException as error:
        metadata['completion_status'] = 'interrupted' if isinstance(error, KeyboardInterrupt) else 'failed'
        metadata['error_type'] = type(error).__name__
        metadata['error'] = str(error)
        metadata['total_seconds'] = time.perf_counter() - start
        # Retain completed cases without replacing a partly written artifact.
        for name, fields, values in [('attempts.csv', ATTEMPT_FIELDS, rows), ('sanity_checks.csv', SANITY_FIELDS, checks)]:
            if not (target / name).exists():
                write_csv(target / name, fields, values)
        save_json(target / 'run_metadata.json', metadata)
        raise
    return target
