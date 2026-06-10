# Fuzz Targets

These targets exercise untrusted Maya scene parsing and execution-surface extraction paths.

Run short local smoke checks with:

```sh
cargo +nightly fuzz run mb_parse -- -runs=1000
cargo +nightly fuzz run ma_selective -- -runs=1000
cargo +nightly fuzz run mel_top_level -- -runs=1000
cargo +nightly fuzz run observe_execution_bytes -- -runs=1000
```

Seed corpora should come only from sanitized public fixtures under `tests/01`, `tests/02`,
and `tests/fixtures`. Do not commit generated corpus growth or crash artifacts unless they
have been minimized and sanitized into generic public fixtures.
