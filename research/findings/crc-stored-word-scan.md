# Stored-word CRC/hash scan

Instrument: `cargo run -q -- crcscan`

The `crcscan` instrument scans dictionary words against the verified engine
stored `u32` values from `ENGINE_MESSAGES`. It tests a pre-committed family of
14 CRC/hash variants and both output byte orders, then reports analytic Poisson
and SplitMix64 empirical false-alarm calibration for the exact dictionary and
target set.

## Positive control

`cargo run -q -- crcscan --self-test` passes.

- `CRC-32/BZIP2("lumikki") = 0x7486f6ac`
- byte-reversed output: `0xacf68674`
- planted scanner recovery: PASS
- SplitMix64 null mean vs analytic lambda: `6.000000e-4` vs `7.029260e-4`

This anchors the CRC reflection and byte-order handling before interpreting any
corpus scan result.

## Default corpus scan

Command:

```sh
cargo run -q -- crcscan
```

Configuration:

- Dictionary: `research/data/crcscan-default-wordlist.txt`, 381 entries.
- Targets: 300 stored `u32`s in 150 engine pairs, 283 unique nonzero `u32`s.
- Digest configurations: 14 variants x 2 output byte orders = 28 per word.

Full hit list:

| word | variant | output order | stored value | location |
| ---- | ------- | ------------ | ------------ | -------- |
| `lumikki` | `CRC-32/BZIP2` | byte-reversed | `0xacf68674` | message 0, pair 0, high |

No other shipped-dictionary word hit the verified eye-corpus stored values.

Calibration:

- Analytic expected spurious hits: `lambda = 7.029260e-4`.
- Observed unique word/config/target hits: `k = 1`.
- Poisson `P(X >= k) = 7.026790e-4`.
- SplitMix64 empirical null, 5000 trials: mean `6.000000e-4`, median `0`, min
  `0`, max `1`, empirical `P(X >= k) = 6.000000e-4`.

## Interpretation

This makes the known `lumikki` match a calibrated candidate mapping anchor, not
a decode. Under the shipped small dictionary the false-alarm rate is about
`7.0e-4`, so the hit is unlikely as a blind coincidence within this exact
search. The strength is dictionary-dependent: with 100000 words and the same
target/config set, lambda would be about `1.844950e-1`, making one hit only
suggestive.

Hypothesis status: `lumikki` remains a candidate Easter-egg / embedded-word-list
anchor until corroborated by additional independent anchors. No lore word beyond
`lumikki` currently looks like a real candidate rather than coincidence.
