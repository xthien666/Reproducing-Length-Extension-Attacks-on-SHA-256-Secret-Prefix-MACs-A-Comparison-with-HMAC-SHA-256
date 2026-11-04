"""Small orchestration primitives and separate CSV schemas (M4, not full runner)."""

import csv
import re
from pathlib import Path

from .attacker import forge_candidate
from .macs import SCHEMES, create_mac, verify_prefix, verify_hmac
from .padding import sha256_padding

ATTEMPT_FIELDS = (
    "run_id", "case_id", "scheme", "repetition_id", "actual_key_len_bytes",
    "message_len_bytes", "original_total_len_bytes", "append_id", "append_len_bytes",
    "guessed_key_len_bytes", "glue_padding_len_bytes", "processed_bytes",
    "forged_message_len_bytes", "original_tag_hex", "forged_tag_hex", "accepted", "attempt_index",
)
SANITY_FIELDS = ("run_id", "case_id", "scheme", "check_type", "expected_accept", "actual_accept", "passed")
VERIFIERS = {"prefix_sha256": verify_prefix, "hmac_sha256": verify_hmac}


def sanity_checks(run_id, case_id, scheme, key, message, append_data):
    """Five independent controls; inputs use the M1 nonempty-message grid."""
    tag = create_mac(scheme, key, message)
    if type(append_data) is not bytes:
        raise TypeError("append_data must be bytes")
    if not message or not append_data:
        raise ValueError("Sanity controls require nonempty message and append_data")
    controls = (
        ("original", message, tag, True),
        ("message_bit_flip", bytes([message[0] ^ 1]) + message[1:], tag, False),
        ("tag_bit_flip", message, bytes([tag[0] ^ 1]) + tag[1:], False),
        ("append_keep_tag", message + append_data, tag, False),
        ("short_tag", message, tag[:-1], False),
    )
    rows = []
    for name, msg, supplied, expected in controls:
        actual = VERIFIERS[scheme](key, msg, supplied)
        rows.append(dict(zip(SANITY_FIELDS, (run_id, case_id, scheme, name, expected, actual, expected == actual))))
    return rows


def scan_case(run_id, case_id, key, message, append_data, append_id,
              repetition_id=0, guesses=range(1, 65)):
    """Return full paired scan; true key/length stay in this orchestrator.

    Guesses must be unique ascending positive ints; no early exit.
    Shorter ranges may be used by unit tests. Production grid remains 1..64.
    """
    guesses = tuple(guesses)
    if any(type(g) is not int for g in guesses):
        raise TypeError("Guesses must be built-in ints")
    if not guesses or guesses != tuple(sorted(set(guesses))) or guesses[0] < 1:
        raise ValueError("Guesses must be unique, ascending and positive")
    rows, controls = [], []
    for scheme in SCHEMES:
        tag = create_mac(scheme, key, message)
        controls.extend(sanity_checks(run_id, case_id, scheme, key, message, append_data))
        for index, guess in enumerate(guesses, 1):
            # The only attacker call: four public arguments, no hidden labels.
            forged_message, forged_tag = forge_candidate(message, tag, append_data, guess)
            accepted = VERIFIERS[scheme](key, forged_message, forged_tag)
            glue_len = len(sha256_padding(guess + len(message)))
            values = (run_id, case_id, scheme, repetition_id, len(key), len(message),
                      len(key) + len(message), append_id, len(append_data), guess, glue_len,
                      guess + len(message) + glue_len, len(forged_message), tag.hex(),
                      forged_tag.hex(), accepted, index)
            rows.append(dict(zip(ATTEMPT_FIELDS, values)))
    return rows, controls


def _validate_rows(rows, fields):
    rows = list(rows)
    if any(set(row) != set(fields) for row in rows):
        raise ValueError("CSV row fields do not match the schema")
    boolean_fields = {"accepted", "expected_accept", "actual_accept", "passed"}
    integer_fields = {"repetition_id", "actual_key_len_bytes", "message_len_bytes",
                      "original_total_len_bytes", "append_len_bytes", "guessed_key_len_bytes",
                      "glue_padding_len_bytes", "processed_bytes", "forged_message_len_bytes", "attempt_index"}
    for row in rows:
        for name, value in row.items():
            expected_type = bool if name in boolean_fields else int if name in integer_fields else str
            if type(value) is not expected_type:
                raise TypeError(f"Invalid CSV field type: {name}")
        if row["scheme"] not in SCHEMES:
            raise ValueError("Invalid CSV scheme")
        if fields == ATTEMPT_FIELDS:
            if any(row[name] < 0 for name in integer_fields):
                raise ValueError("Negative CSV count")
            if row["guessed_key_len_bytes"] < 1 or row["attempt_index"] < 1:
                raise ValueError("Scan guesses and indices must be positive")
            for name in ("original_tag_hex", "forged_tag_hex"):
                if re.fullmatch(r"[0-9a-f]{64}", row[name]) is None:
                    raise ValueError("Tag must be 32 bytes in lowercase hex")
        elif row["check_type"] not in {"original", "message_bit_flip", "tag_bit_flip", "append_keep_tag", "short_tag"}:
            raise ValueError("Unknown sanity check")
    return rows


def write_case_results(results_root, run_id, attempts, controls, extra_attempts=()):
    """Write three separate CSVs into a new run directory; never overwrite."""
    if type(run_id) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", run_id) is None:
        raise ValueError("run_id must be a simple alphanumeric/underscore/hyphen identifier")
    attempts = _validate_rows(attempts, ATTEMPT_FIELDS)
    controls = _validate_rows(controls, SANITY_FIELDS)
    extras = _validate_rows(extra_attempts, ATTEMPT_FIELDS)
    if any(row["run_id"] != run_id for row in attempts + controls + extras):
        raise ValueError("Row run_id mismatch")
    for group, identity in [(attempts, ("case_id", "scheme", "guessed_key_len_bytes")),
                            (extras, ("case_id", "scheme", "guessed_key_len_bytes")),
                            (controls, ("case_id", "scheme", "check_type"))]:
        keys = [tuple(row[k] for k in identity) for row in group]
        if len(keys) != len(set(keys)):
            raise ValueError("Duplicate rows")
    target = Path(results_root) / run_id
    target.mkdir(parents=True, exist_ok=False)
    for filename, fields, rows in [
        ("attempts.csv", ATTEMPT_FIELDS, attempts),
        ("sanity_checks.csv", SANITY_FIELDS, controls),
        ("extra_attempts.csv", ATTEMPT_FIELDS, extras),
    ]:
        with (target / filename).open("x", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
    return target
