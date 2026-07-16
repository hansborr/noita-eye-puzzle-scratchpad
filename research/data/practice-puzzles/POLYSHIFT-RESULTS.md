# Position-polynomial shift results — letter puzzles

The `polyshift` instrument exhaustively tested the remaining practice letter
puzzles against a bounded position-keyed family:

```text
k_i = a*i*(i-1)/2 + b*i + c (mod 26)
```

Both additive (`C = P + K`) and Beaufort (`C = K - P`) readouts are included.
Setting `a=0` includes every linear progressive shift. The degree-two sweep is
35,152 parameter/readout cells per ciphertext. It is exhaustive within this
family; it is not a generic solver for arbitrary aperiodic keystreams.

The integer-valued binomial basis is deliberate: odd `a` produces period-52
keystreams, so this includes a constant-second-difference surface not already
covered by the repository's period-`<=40` profile. Even-`a` and linear cells
overlap shorter-period negatives; the matched null pays for the full registered
surface regardless.

## Controls and gate

The instrument runs its positive control before touching real input. A planted
degree-two English cipher (`a=5, b=7, c=11`) was recovered with 1.000 plaintext
accuracy and exact replay. In the registered 32-null run it cleared the full
max-over-family matched-null gate at `z=130.83`, margin `4.155` mean-log nats.

For every real and null stream, selection is over the same complete 35,152-cell
surface. Each null Fisher–Yates-shuffles the ciphertext letters, preserving the
unigram multiset, and reruns the entire sweep. Survival requires exact replay,
`z >= 6`, and an absolute score margin of at least `1` nat.

## Result (2026-07-16)

No puzzle survived. Best candidates are gibberish and sit at the matched-null
floor:

| Puzzle | Best convention / `(a,b,c)` | score | null mean | margin | z | verdict |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| `three` | Beaufort / `(25,21,11)` | -13.924937 | -13.906751 | -0.018186 | -0.352 | honest negative |
| `four` | Beaufort / `(2,15,16)` | -13.825603 | -13.822669 | -0.002935 | -0.044 | honest negative |
| `five` | additive / `(24,16,18)` | -14.116748 | -14.126853 | 0.010105 | 0.286 | honest negative |
| `seven` | additive / `(9,16,20)` | -13.967985 | -13.941206 | -0.026779 | -0.389 | honest negative |

The table excludes only degree-at-most-two position-polynomial shifts modulo 26
under the two registered readouts. It does not exclude running keys, long-primer
plaintext autokey, Alberti/index-marker constructions, arbitrary position tables,
or other aperiodic polyalphabetic ciphers. This classical-cipher negative does not
transfer to the Noita eyes' group-autokey setting.

## Reproduce

```sh
cargo run --release --locked -- polyshift \
  --input-file research/data/practice-puzzles/five \
  --alphabet ABCDEFGHIJKLMNOPQRSTUVWXYZ --degree 2 \
  --null-trials 32 --seed 0x706f6c7973686966
```

The output labels any survivor a candidate rather than a decode; only external
ground-truth confirmation could close a practice puzzle.
