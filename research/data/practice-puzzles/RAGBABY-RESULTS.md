# General Ragbaby attack — calibrated heuristic results

Status: **no tested run on `three`, `four`, `five`, or `seven` produced a
surviving candidate**. This is not an exhaustive search over the 24!/25!/26!
keyed alphabets. It is a bounded simulated-annealing result whose strength is
reported through target-length positive controls.

## Method and bounds

The unknown Ragbaby keyed alphabet is an arbitrary permutation. For each tested
convention, the optimizer uses English quadgram likelihood, random restarts, a
geometric temperature schedule, transposition/slide/segment-reversal moves, and
basin hopping. It searches rather than enumerates the factorial keyspace.

The exact outer grid was:

```text
bases {24,25,26}
× numbering {standard, per-word, continuous}
× signs {+,-}
= 18 convention cells per puzzle.
```

Reduced bases permute the retained letters in their real A..Z indices: base 25
folds J→I, while base 24 also folds V→U. The same production search is rerun on
shuffled ciphertext for the matched null. A survivor needs `z >= 6`, at least a
1-nat margin on the mean quadgram-score scale, exact encrypt/decrypt replay, and
an odd-fold advantage over the matched odd-fold null.

## Result and measured recovery power

Positive controls encrypt approximately matched target-length English under
random keyed alphabets and count a recovery when plaintext accuracy reaches at
least 0.9. The reported rates are finite empirical trials, not guarantees.

| Puzzle | Letters | Matched base | Planted recovery | Best real matched z | Bounded verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| `five` | 274 | 25 | 1.00 (8 trials) | 3.11 | strongest negative; no survivor |
| `seven` | 152 | 26 | 0.83 (6 trials) | 1.90 | no survivor; moderate control power |
| `three` | 139 | 24 | 0.80 (10 trials) | 5.63 screen → 0.33 at 32 nulls | no survivor; screen hit was unstable |
| `four` | 121 | 24 | 0.70 (10 trials) | 3.10 | no survivor; weakest/shortest case |

The important claim is therefore not “these puzzles cannot be Ragbaby.” Under
the recorded optimizer and convention grid, the real puzzles did not survive
the full gate. The same optimizer recovered target-length plants at the rates
above, and a separate planted regression verifies that a recovered plant can
clear the full gate. The evidence is strongest for `five` and weakest for
`four`.

For `seven`, treating `#` as a deleted null or a word break also produced no
survivor. Treating it as an Alberti-style rotation index is a different model and
remains open. Punctuation-as-keyed-alphabet and running-key models are also out
of scope.

The reusable implementation lessons—sum rather than mean annealing objective,
real-letter indexing for reduced bases, and fold-vs-fold held-out calibration—
are kept in `../../attack-methodology.md` rather than repeated as a development
changelog here.

## Reproduce

```sh
cargo build --release --locked

# New eight-trial replication of the planted-recovery grid. The recorded table
# combines historical 6-, 8-, and 10-trial runs.
./target/release/noita-eye ragbaby --control \
  --control-lengths 121,139,152,274 --control-trials 8 \
  --bases 24,25,26 --restarts 150

# Full convention grid on one puzzle.
./target/release/noita-eye ragbaby --puzzle five \
  --bases 24,25,26 --numbering std,perword,continuous \
  --sign both --restarts 80 --matched-null-trials 12 --seed 1
```
