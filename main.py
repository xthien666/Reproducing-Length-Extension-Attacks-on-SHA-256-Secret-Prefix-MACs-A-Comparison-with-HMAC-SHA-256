"""Local demo, persistent fixtures, and configured pilot/main experiments."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform

from src.attacker import forge_candidate
from src.experiment import scan_case, write_case_results, VERIFIERS
from src.macs import SCHEMES, create_mac
from src.padding import sha256_padding

ROOT = Path(__file__).resolve().parent


def demo(run_id, results_root=None):
    # Publicly documented lab fixture for reproducibility, never read by attacker.
    key, message, suffix = bytes(range(16)), bytes(range(32)), b';role=admin'
    rows, checks = scan_case(run_id, 'case-001', key, message, suffix, 'role_admin')
    examples = []
    for scheme in SCHEMES:
        original_tag = create_mac(scheme, key, message)
        for guess in (15, 16, 17):
            forged, tag = forge_candidate(message, original_tag, suffix, guess)
            glue = sha256_padding(guess + len(message))
            examples.append({
                'scheme': scheme, 'message_hex': message.hex(), 'append_hex': suffix.hex(),
                'original_tag_hex': original_tag.hex(), 'guessed_key_len_bytes': guess,
                'glue_padding_hex': glue.hex(), 'glue_padding_len_bytes': len(glue),
                'encoded_bit_length': int.from_bytes(glue[-8:], 'big'),
                'processed_bytes': guess + len(message) + len(glue),
                'forged_message_hex': forged.hex(), 'forged_message_len_bytes': len(forged),
                'forged_tag_hex': tag.hex(), 'accepted': VERIFIERS[scheme](key, forged, tag),
            })
    accepted = {s: [r['guessed_key_len_bytes'] for r in rows if r['scheme'] == s and r['accepted']] for s in SCHEMES}
    passed = (len(rows) == 128 and len(checks) == 10 and all(r['passed'] for r in checks)
              and accepted == {'prefix_sha256': [16], 'hmac_sha256': []})
    target = write_case_results(results_root or ROOT / 'results', run_id, rows, checks)
    (target / 'demo.json').write_text(json.dumps({
        'run_id': run_id, 'case_id': 'case-001', 'fixture_recipe': {
            'key': 'bytes(range(16))', 'message': 'bytes(range(32))', 'append_hex': suffix.hex()},
        'actual_key_len_bytes': len(key), 'examples': examples,
    }, indent=2) + '\n', encoding='utf-8')
    source_files = sorted((ROOT / 'src').glob('*.py')) + [ROOT / 'main.py']
    metadata = {
        'run_id': run_id, 'profile': 'm3-m4-demo', 'status': 'completed' if passed else 'failed',
        'created_utc': datetime.now(timezone.utc).isoformat(),
        'command': f'python main.py demo --run-id {run_id}',
        'python_version': platform.python_version(), 'platform': platform.platform(),
        'base_cases': 1, 'attempt_rows': len(rows), 'sanity_rows': len(checks),
        'sanity_passed': sum(r['passed'] for r in checks), 'extra_rows': 0, 'e5_enabled': False,
        'accepted_guesses': accepted, 'guess_range': [1, 64], 'early_stop': False,
        'extra_file_note': 'Header only; E5 was not run.',
        'scope': 'One deterministic lab case, not the configured pilot or main grid.',
        'source_sha256': {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in source_files},
        'artifact_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(target.iterdir()) if p.is_file()},
    }
    (target / 'run_metadata.json').write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8')
    if not passed:
        raise RuntimeError(f'Demo failed; retained evidence at {target}')
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['demo', 'generate-fixtures', 'experiment'])
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--config', type=Path, default=ROOT / 'config/experiment.json')
    parser.add_argument('--profile', choices=['pilot', 'main'], default='pilot')
    parser.add_argument('--fixtures', type=Path, help='Reuse saved fixtures.json and sibling public_cases.json')
    args = parser.parse_args()
    if args.command == 'demo':
        print(demo(args.run_id))
    else:
        from src.runner import generate_fixtures, load_config, run_experiment
        if args.command == 'generate-fixtures':
            if args.fixtures is not None:
                parser.error('--fixtures applies only to experiment')
            config, _ = load_config(args.config, args.profile)
            print(generate_fixtures(config, args.profile, args.run_id, ROOT / 'data'))
        else:
            print(run_experiment(args.config, args.profile, args.run_id, args.fixtures))


if __name__ == '__main__':
    main()
