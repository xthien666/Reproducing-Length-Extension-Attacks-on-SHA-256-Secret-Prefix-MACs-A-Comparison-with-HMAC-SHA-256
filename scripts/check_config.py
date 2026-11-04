"""Validate the M1 configuration and compute planned counts; run no attacks."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = PROJECT_ROOT / "config" / "experiment.json"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, label, minimum=0):
    require(type(value) is int and value >= minimum,
            f"{label} must be an integer >= {minimum}")
    return value


def integer_list(values, label, minimum=1):
    require(type(values) is list and len(values) > 0, f"{label} must be a nonempty list")
    for value in values:
        integer(value, label, minimum)
    require(len(values) == len(set(values)), f"{label} contains duplicates")
    return values


def padding_length(n):
    return 1 + (55 - n) % 64 + 8


def validate_config(config):
    require(type(config) is dict, "Configuration must be a JSON object")
    require(type(config["schema_version"]) is int and config["schema_version"] == 1,
            "Only schema_version 1 is supported")
    require(config["project_id"] == "sha256-length-extension", "Unexpected project_id")
    h = config["hash"]
    require(h["name"] == "sha256", "Expected sha256")
    require(integer(h["block_size_bytes"], "block size", 1) == 64, "Block size must be 64")
    require(integer(h["digest_size_bytes"], "digest size", 1) == 32, "Digest size must be 32")
    require(h["tag_truncation"] is False, "M1 requires full-length tags")
    schemes = config["schemes"]
    require(schemes == ["prefix_sha256", "hmac_sha256"], "Expected the two M1 schemes")

    grid = config["grid"]
    key_lengths = integer_list(grid["key_lengths_bytes"], "key lengths")
    totals = integer_list(grid["original_total_lengths_bytes"], "original totals")
    require(key_lengths == [8, 16, 32, 48], "Key lengths differ from the agreed M1 grid")
    require(totals == [55, 56, 63, 64, 119, 120, 127, 128],
            "Original total lengths differ from the agreed M1 grid")
    require(grid["message_length_rule"] == "original_total_length_bytes - key_length_bytes",
            "Unexpected message length rule")
    require(min(totals) > max(key_lengths), "Every message must be nonempty for the bit-flip check")
    require(max(totals) < (1 << 61), "Original message exceeds SHA-256 byte-length domain")
    guesses = grid["guessed_key_length_bytes"]
    first = integer(guesses["start_inclusive"], "first guess", 1)
    last = integer(guesses["end_inclusive"], "last guess", first)
    require((first, last) == (1, 64), "The main grid must use guesses 1..64 inclusive")
    require(all(first <= k <= last for k in key_lengths), "Main keys must lie in the guess range")
    require(guesses["order"] == "ascending", "Guess order must be ascending")
    require(grid["scan_policy"] == "exhaustive_without_early_stop", "All guesses must be recorded")
    require(grid["continuation_cache"] is False, "These operation counts assume no cache")

    payloads = grid["append_payloads"]
    require(type(payloads) is list and len(payloads) > 0, "Missing append payloads")
    decoded = {}
    for payload in payloads:
        payload_id = payload["id"]
        require(type(payload_id) is str and len(payload_id) > 0, "Invalid payload id")
        require(payload_id not in decoded, "Duplicate payload id")
        require(payload["encoding"] == "hex", "Payloads must use hex encoding")
        value = payload["data"]
        require(type(value) is str and re.fullmatch(r"(?:[0-9a-f]{2})+", value) is not None,
                f"{payload_id} must contain nonempty lowercase hex byte pairs")
        data = bytes.fromhex(value)
        require(len(data) == integer(payload["length_bytes"], "payload length", 1),
                f"{payload_id} length mismatch")
        decoded[payload_id] = data
    require(decoded.get("role_admin") == b";role=admin", "role_admin bytes mismatch")
    require(decoded.get("bytes_00_to_4f") == bytes(range(80)), "Binary payload bytes mismatch")
    require(len(decoded) == 2, "M1 uses exactly two payloads")
    # Bound both the continuation's logical length and the real verifier input.
    for key_len in key_lengths:
        for total in totals:
            message_len = total - key_len
            for guess in range(first, last + 1):
                prefix_len = guess + message_len
                require(prefix_len < (1 << 61), "Guessed prefix is too long")
                glue_len = padding_length(prefix_len)
                for data in decoded.values():
                    require(prefix_len + glue_len + len(data) < (1 << 61), "Continuation too long")
                    require(total + glue_len + len(data) < (1 << 61), "Verifier input too long")

    checks = config["sanity_checks"]
    expected_checks = {
        "original": True, "message_bit_flip": False, "tag_bit_flip": False,
        "append_keep_tag": False, "short_tag": False,
    }
    require(type(checks) is list and len(checks) == 5, "Expected five sanity checks")
    require(len({c["id"] for c in checks}) == 5, "Duplicate sanity check id")
    require({c["id"]: c["expected_accept"] for c in checks} == expected_checks,
            "Sanity check expectations mismatch")
    require(all(type(c["expected_accept"]) is bool for c in checks), "Sanity expectations must be bool")

    fixtures = config["fixtures"]
    require(fixtures["key_generator"] == fixtures["message_generator"] == "secrets.token_bytes",
            "Unexpected fixture generators")
    require(fixtures["sampling"] == "independent_key_and_message_per_base_case", "Unexpected sampling")
    require(fixtures["scheme_pairing"] == "same_key_message_and_append_data", "Pairing mismatch")
    require(fixtures["rerun_policy"] == "reuse_saved_fixtures", "Reruns must reuse fixtures")
    require(fixtures["bytes_encoding_on_disk"] == "hex", "Fixture encoding must be hex")
    require(fixtures["public_case_fields"] == [
        "case_id", "message_hex", "append_id", "append_hex", "tags_by_scheme"
    ], "Public cases must not expose keys, key lengths, seeds or internal states")
    require(fixtures["private_path_template"] == "data/{run_id}/fixtures.json", "Private path mismatch")
    require(fixtures["public_path_template"] == "data/{run_id}/public_cases.json", "Public path mismatch")
    storage = config["storage"]
    require(storage["run_directory_template"] == "results/{run_id}", "Run path mismatch")
    require(storage["existing_run_policy"] == "fail_if_exists", "Existing runs must be preserved")
    require(storage["counts_exclude_csv_header"] is True, "Counts must exclude headers")
    require(storage["attempt_unique_key"] == ["run_id", "case_id", "scheme", "guessed_key_len_bytes"],
            "Unexpected attempt key")
    require(storage["files"] == {
        "metadata": "run_metadata.json", "attempts": "attempts.csv",
        "sanity_checks": "sanity_checks.csv", "extra_attempts": "extra_attempts.csv",
        "summary": "summary.csv",
    }, "Output file contract mismatch")

    profiles = config["profiles"]
    require(set(profiles) == {"pilot", "main"}, "Expected pilot and main profiles")
    summaries = {}
    for name, profile in profiles.items():
        repetitions = integer(profile["repetitions_per_combination"], f"{name} repetitions", 1)
        require(repetitions == (1 if name == "pilot" else 10), "M1 profile repetition mismatch")
        combinations_per_payload = len(key_lengths) * len(totals) * repetitions
        cases = combinations_per_payload * len(decoded)
        pairs = cases * len(schemes)
        attempt_count = pairs * (last - first + 1)
        blocks_per_payload = sum((len(x) + padding_length(len(x))) // 64 for x in decoded.values())
        blocks = combinations_per_payload * len(schemes) * (last - first + 1) * blocks_per_payload
        counts = {
            "base_cases": cases, "case_scheme_pairs": pairs,
            "candidate_attempts": attempt_count, "sanity_checks": pairs * len(checks),
            "attacker_continuation_calls": attempt_count, "attacker_compression_blocks": blocks,
        }
        expected = profile["expected_counts"]
        require(set(expected) == set(counts), f"{name} count fields mismatch")
        for field, value in counts.items():
            require(integer(expected[field], field) == value, f"{name}.{field} mismatch")
        summaries[name] = counts

    extra = config["extra_experiment"]
    require(extra["id"] == "E5" and type(extra["enabled"]) is bool, "Invalid E5 settings")
    require(integer(extra["key_length_bytes"], "E5 key length", 1) == 80, "E5 key length must be 80")
    require(integer(extra["message_length_bytes"], "E5 message length", 1) == 32, "E5 message length must be 32")
    require(extra["append_payload_id"] == "role_admin", "E5 payload mismatch")
    require(extra["scheme_policy"] == "both_configured_schemes", "E5 schemes mismatch")
    require(extra["guess_policy"] == "reuse_main_guess_range", "E5 guesses mismatch")
    require(extra["include_in_main_counts"] is False, "E5 must remain separate")
    require(integer(extra["expected_candidate_attempts_if_enabled"], "E5 attempts") ==
            len(schemes) * (last - first + 1), "E5 count mismatch")
    return summaries


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    args = parser.parse_args()
    try:
        raw = args.config.read_bytes()
        config = json.loads(raw.decode("utf-8"))
        summaries = validate_config(config)
    except (OSError, UnicodeError, ValueError, KeyError, TypeError) as error:
        print(f"M1 config validation failed: {error}", file=sys.stderr)
        return 1
    report = {
        "status": "passed",
        "scope": "M1 configuration validation only; no cryptographic experiment executed",
        "python_version": sys.version.split()[0],
        "config_file": args.config.resolve().as_posix(),
        "config_sha256": hashlib.sha256(raw).hexdigest(),
        "validator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "planned_profiles": summaries,
        "extra_experiment_enabled": config["extra_experiment"]["enabled"],
        "extra_candidate_attempts_if_enabled": config["extra_experiment"]["expected_candidate_attempts_if_enabled"],
        "cryptographic_tests_run": False,
        "experiment_results_exist_from_this_check": False,
    }
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
