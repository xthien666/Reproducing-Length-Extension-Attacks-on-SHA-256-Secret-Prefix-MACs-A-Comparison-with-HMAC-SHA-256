# Reproducing Length-Extension Attacks on SHA-256 Secret-Prefix MACs

This experiment compares SHA-256 secret-prefix MACs with HMAC-SHA-256. The attacker receives the message, original tag, suffix and a guessed key length. The verifier holds the key. Each pair of constructions uses the same synthetic key, message and suffix.

## Run locally

The recorded run used Python 3.14.7. The runner and tests use the Python standard library. Run these commands from the repository root:

```sh
python -m unittest discover -s tests -v
python main.py demo --run-id demo-local
python main.py experiment --profile main --run-id replay-local
```

Use a fresh run ID for each execution. The runner writes and audits its CSV files under `results/<run-id>/`. The main command generates synthetic keys and messages for a fresh run. The attacker receives only public inputs through its function interface.

## Recorded results

| Construction | Cases with a valid forgery | Accepted candidates |
| --- | ---: | ---: |
| SHA-256 secret-prefix MAC | 640/640 | 640/40,960 |
| HMAC-SHA-256 | 0/640 | 0/40,960 |

Each construction was evaluated with 64 guesses per case. All 6,400 sanity checks passed. The observed HMAC result applies to the transformation and inputs tested here.

## References

- [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf), sections 5.1.1 and 6.2.
- [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104.html#section-2), section 2.
- [RFC 4231](https://www.rfc-editor.org/rfc/rfc4231.html#section-4), HMAC test vectors.
