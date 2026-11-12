# passcheck-rs

Offline password strength auditor in Rust with zero dependencies. It prices recognisable structure (common passwords, leetspeak variants, keyboard walks, sequences, repeats, years) far below random characters, the way a cracking tool would, and estimates crack time for an online and an offline attacker.

> Built with AI assistance (Claude) as part of a security portfolio.

## Why it is safe to use

- The password is read from **stdin only**, never from arguments (those leak into shell history and process lists).
- The password is **never printed**, including in batch mode, which reports only line numbers and verdicts. A test enforces this.
- Everything runs offline. No network, no dependencies.

## Usage

```bash
cargo build --release
echo 'P@ssw0rd' | ./target/release/passcheck            # exit 1: weak
printf 'garden violin sunrise pocket marble\n' | ./target/release/passcheck
./target/release/passcheck --batch --min-score 3 < candidates.txt
```

Exit codes: 0 all passwords meet `--min-score` (default 3), 1 at least one is below it, 2 usage error.

## Scoring

Entropy is estimated from the character pool of the unstructured part, plus a small fixed cost for the structured part. Common passwords (after leet normalisation and stripping trailing digits or symbols) are capped at a few bits. Score 0 to 4 maps to very weak, weak, fair, strong, very strong. Crack time assumes 100 guesses/s online and 10^10 guesses/s offline against a fast hash, and halves the keyspace for the average case.

## Limits

The bundled common password list is a small sample. This is an estimator, not a guarantee: always combine it with a breach list check and MFA.

## Tests

`cargo test` covers detection of each pattern, score monotonicity, passphrases vs short complex passwords, Unicode length, empty and huge inputs, and the CLI contract. CI runs on Linux, macOS and Windows with clippy `-D warnings`.

MIT licensed.
