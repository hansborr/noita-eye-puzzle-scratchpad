# Practice `two` pair-IC class ranking

Instrument: `shadowpairic` (Phase 0 pair-value IC ranker).

Status: measured on 2026-07-06 from a regenerated `shadowsearch --output`
artifact for committed practice puzzle `two`.

## Commands

Artifact generation:

```sh
cargo run --release -q -- shadowsearch --input-file research/data/practice-puzzles/two --alphabet ABCDEFGHIJKL --output target/two-shadowsearch.json
```

Pair-IC ranking:

```sh
cargo run --release -q -- shadowpairic --artifact target/two-shadowsearch.json
```

## Self-validation

The ranker self-test passed before real artifact output:

- random injective 6-bit table + random 8! label-to-digit permutation +
  random HL/LH order preserved pair-IC exactly (`delta = 0.000e0`);
- the transformed stream decoded back to the planted English control;
- matched flat null was far from English IC (`flat IC = 0.012927`, distance
  from `0.066700` = `0.053773`).

## Result

Interpretation: **flat/diffuse, not sharply peaked**. Eight rows are inside the
instrument's English-like window (`0.066700 +/- 0.0075`), and the best-vs-second
distance gap is only `0.000198`. Pair-IC therefore orders later finish work but
does not collapse the class axis to one class.

Class indices below are zero-based, matching `shadowfinish` reports.

| rank | class | pairs | pair IC | distance from 0.066700 |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 9 | 349 | 0.065705 | 0.000995 |
| 2 | 15 | 349 | 0.065507 | 0.001193 |
| 3 | 0 | 349 | 0.065376 | 0.001324 |
| 4 | 3 | 349 | 0.065376 | 0.001324 |
| 5 | 6 | 349 | 0.065376 | 0.001324 |
| 6 | 14 | 349 | 0.065376 | 0.001324 |
| 7 | 16 | 349 | 0.065376 | 0.001324 |
| 8 | 17 | 349 | 0.065376 | 0.001324 |
| 9 | 2 | 349 | 0.042700 | 0.024000 |
| 10 | 10 | 349 | 0.042404 | 0.024296 |
| 11 | 1 | 349 | 0.042321 | 0.024379 |
| 12 | 12 | 349 | 0.042321 | 0.024379 |
| 13 | 20 | 349 | 0.042272 | 0.024428 |
| 14 | 18 | 349 | 0.042206 | 0.024494 |
| 15 | 4 | 349 | 0.042173 | 0.024527 |
| 16 | 7 | 349 | 0.042173 | 0.024527 |
| 17 | 19 | 349 | 0.042173 | 0.024527 |
| 18 | 21 | 349 | 0.042173 | 0.024527 |
| 19 | 11 | 349 | 0.042058 | 0.024642 |
| 20 | 13 | 349 | 0.042058 | 0.024642 |
| 21 | 5 | 349 | 0.042041 | 0.024659 |
| 22 | 23 | 349 | 0.042041 | 0.024659 |
| 23 | 8 | 349 | 0.042008 | 0.024692 |
| 24 | 22 | 349 | 0.042008 | 0.024692 |

## Claim ceiling

Pair-IC is invariant under the finish surface's label-to-digit permutation,
HL/LH transpose, and injective 6-bit table relabeling, so it is a free class-axis
ranker and necessary-condition filter. It is one feature only. At `N = 349`, a
junk class can land near English IC by chance, and this result is not a decode,
candidate, or acceptance verdict.
