# Small-alphabet practice puzzles — durable results

This is the current result record for `one`, `two`, and `six`. It describes the
successful route, the bounded search surfaces, and the claim ceiling. Historical
campaign detail belongs in the linked findings and handoffs, not in this summary.

| Puzzle | Status | Recovered mechanism or candidate |
| --- | --- | --- |
| `one` | **Verified decode** (2026-07-01) | alternating-orientation walk on C5, then 7-bit ASCII; exact 266/266 ciphertext replay |
| `two` | **Maintainer-confirmed plaintext** (2026-07-06) | full-symbol isomorph maps → order-48 shadow search → output interpretation → monoalphabetic finish |
| `six` | **Exact candidate** (2026-07-15) | cube-face walk → three roll directions → Morse; 139/139 replay on all three lines |

The strongest claims differ deliberately. `one` has a fixed-codec original-
ciphertext round trip. `two` was checked against withheld plaintext, but the
original generator/key/codec artifacts needed for an independent generator
round trip are unavailable. `six` has an exact replay and a strong null result,
but its missing pre-stream cube face leaves a first-mark ambiguity. See
`TWO-WITHHELD-CONFIRMATION-FREEZE.md`,
`../../findings/two-original-generator-roundtrip-blocker.md`, and
`SIX-RESULTS.md`.

## `one`: alternating orientation + 7-bit ASCII

Plaintext:

```text
Permutation Representation Destination
```

The 266 ciphertext digits form a ±1 walk on C5. Let the observed direction at
step `i` be `o_i` and use the deterministic orientation mask `b_i = i mod 2`.
Then `o_i XOR b_i` gives bits 2..266 of the MSB-first 7-bit ASCII plaintext.
The first bit is not carried by a transition; the six recovered head bits have
only one printable completion, `P`.

This was found by enumerating the small closure of one-bit orientation-update
conventions and testing fixed-width readouts. It was not selected by an n-gram
search. `maskdecode` enumerates the bounded convention grid and accepts only a
full-letter reading that exactly re-encodes the ciphertext. The result replays
all 266 digits.

```sh
cargo run -q -- maskdecode \
  --input-file research/data/practice-puzzles/one --alphabet 01234
cargo run -q -- maskdecode --self-test
```

Earlier attacks on `one` remain valid only for the surfaces they actually
tested. They are useful as method checks, not as steps needed to reproduce the
solve:

| Instrument | Tested surface | Durable result |
| --- | --- | --- |
| `solve --codec-search` | fixed grouping/projection codecs | no gated survivor; a many-to-one English-looking overfit was rejected |
| `rlcodec` / `codecpower` | memoryless readings of the direction-blind run-length carrier | no above-first-order signal; the gate has little measured power at this short length |
| `cribfit` | crib-aligned periodic/stateful carrier codecs | run-period must be 1; bit-period must divide 21; tested viable periods did not survive |
| `rankcodec` / `mdlcodec` | bounded predictive-rank and affine running-key families | no crib-admissible or null-clearing candidate within their stated grids |
| `bigramcodec` | directed edges and magnitude pairs | structural correlation, no readable candidate; order-1 null is powerless for a bigram objective |

These searches reduced the direction stream in ways that discard the actual
alternating polarity. Their negatives therefore do not conflict with the solve.
This is the motivating example for re-auditing exclusions when the model class
changes; see `../../attack-methodology.md` §7.

## `two`: how the attack actually worked

The successful route used the full 12-symbol stream. Earlier work projected it
to a four-class or mod-3 channel and treated it as `C3 × H`; that direct-product
interpretation is superseded. The mod-3 forbidden-transition law and the repeat
locations remain measured facts, but the projection threw away the symbol
bijections that exposed the group.

### 1. Repeated-pattern maps exposed an order-48 shadow

`isomap` found long pairs of substrings with the same equality pattern. Aligning
such a pair gives a partial ciphertext-symbol bijection, or *column map*.
Consistent maps were chained and closed under composition. Four full maps
generated a transitive permutation group of order 48 on the 12 observed labels,
with point stabilizer size 4.

The repeats were tested against an order-1 Markov null fitted to the observed
transition law. Their raw boundaries extend 1–2 positions by chance, so hard
constraints trim two symbols from each end. The independent solver reported that
untrimmed anchors rejected the true shadow candidate; the committed self-test
reproduces that failure mode with a dirty-boundary planted control.

The order 48 is a lower bound, not the reported true group order. All strong
anchor gaps are even, so the observed maps can be trapped in an index-2
subgroup. The puzzle author reportedly identified an order-96 group; the
committed search below operates only in the order-48 observable shadow.

```sh
cargo run --release -q -- isomap \
  --input-file research/data/practice-puzzles/two --alphabet ABCDEFGHIJKL
cargo run --release -q -- isomap --self-test
```

### 2. The 3.1-million-key stage was structured exhaustive search

Once the shadow group was known, a key in this model had:

- one initial state `u_-1` in the order-48 group; and
- for each of eight legal readout values, one of four group elements in the
  corresponding point-stabilizer fiber.

Therefore the complete shadow-key space was

```text
48 × 4^8 = 3,145,728.
```

`shadowsearch` enumerated every one of those keys. It was brute force in this
precise, constrained sense, but not blind trial decryption and not a brute force
of arbitrary group actions or plaintexts. The implementation streamed the keys,
checked full-stream legality, and rejected them early on the first trimmed
repeat. Only first-pass survivors received a full 698-position derived history
and the remaining hard-anchor checks.

```text
3,145,728 structured keys
    835,520 pass the first hard anchor
    104,096 distinct derived streams pass all hard anchors
         96 reach the best short-repeat score (12/17)
         24 remain after quotienting global relabelings
```

The release run was reported at about 15 seconds. Its output is a list of
order-48 quotient candidates; it is not a recovered order-96 key.

```sh
cargo run --release -q -- shadowsearch \
  --input-file research/data/practice-puzzles/two \
  --alphabet ABCDEFGHIJKL --output target/two-shadowsearch.json
cargo run --release -q -- shadowsearch --self-test
```

### 3. Finishing still required a separate search

The independent attack that first exposed this pipeline could not choose the
last interpretation by language scoring alone and used a 103-letter crib. The
repo then reproduced the structural stages and, after correcting the finish
discriminator, surfaced the following candidate without that crib.

The 24 canonical streams did not directly spell plaintext. `shadowfinish`
searched the bounded output surface:

```text
24 classes × 8! digit relabelings × 2 digit orders × 7 tables
= 13,547,520 interpretations.
```

The search uses explicit top-K retention, so later language scoring is bounded
rather than exhaustive over every retained-path variant. Pair-value index of
coincidence (`shadowpairic`) provided a free class ranker but did not isolate one
class. After the finish discriminator was corrected, the selected candidate
cleared its conditional matched null (`0/49`, add-one `p = 0.0200`). That null is
conditional on the retained max-soft shadow classes; it does not replay all
104,096 stage-2 survivors.

The output still contained a 26-symbol monoalphabetic layer with spaces.
`substfinish` used simulated annealing plus a space-preserving matched null to
recover the readable letter-level passage (`0/20`, add-one `p = 0.0476`). The
maintainer then confirmed it against withheld ground truth. Punctuation,
hyphenation, quotation marks, and the repair of the opening word were restored
from syntax/source alignment, not recovered by the instrument.

The confirmed content asks whether an octal number system could predate decimal,
then discusses the proposed Proto-Indo-European relationship between “nine” and
“new” and the slim evidence for octal use. The exact recorded output, command,
and claim ceiling live in
`../../findings/two-shadowfinish-substitution-candidate.md`.

Reproduce the committed 49-null finish from a freshly generated artifact:

```sh
cargo run --release -q -- shadowfinish \
  --input-file research/data/practice-puzzles/two \
  --alphabet ABCDEFGHIJKL --artifact target/two-shadowsearch.json \
  --word-corpus-file research/data/lang/english-corpus-large.txt \
  --null-trials 49 --seed 0x736861646f776603
```

### Would a slightly larger group break this approach?

The current enumerator costs

```text
|G| × product of the legal-readout fiber sizes.
```

For a transitive action on 12 labels, each fiber has size `|G| / 12`. With the
same eight legal readouts, the analogous cost grows as
`|G| × (|G|/12)^8`, not merely linearly with group order. Moving from the
order-48 shadow to the reported order-96 group would change the naive space to

```text
96 × 8^8 = 1,610,612,736,
```

which is 512 times larger. That does not make the method logically fail, and
better constraint propagation, quotient/lift search, or parallelism could make
it tractable. It does mean that the pleasant exhaustive loop used for 3.1
million candidates stops scaling quickly. It is not a plausible direct route to
the eyes' `{A83, S83}`-scale setting.

For the detailed evidence trail and stage mechanics, see
`../../handoff/two-cross-agent-recon.md`. For the final result, see
`../../findings/two-shadowfinish-substitution-candidate.md` and
`TWO-WITHHELD-CONFIRMATION-FREEZE.md`.

## `six`: cube/Morse exact candidate

The three 139-symbol lines are fixed relabelings of one cube-face trace. Each
transition is a legal roll; the three roll directions read as Morse dot, dash,
and letter separator, while the visible spaces remain word separators. This
gives:

```text
CUBE IS A GREAT TOY MODEL OF NON-COMMUTATIVITY.
```

All three lines replay 139/139 positions, and none of 1,024 registered matched
nulls produced an all-valid Morse candidate. Because the face before the first
symbol is not observed, another exact completion begins `FUBE`; the natural
reading is therefore an exact candidate rather than a formally unique decode.
Commands, controls, and the Python/Rust cross-check are in `SIX-RESULTS.md`.

## What not to infer

- A passing language score is a candidate, not a decode. `two` was promoted
  because the maintainer checked withheld plaintext; its current replay inside
  the co-searched output interpretation is not independent evidence.
- The order-48 closure for `two` is an observed shadow, not proof that the true
  group has order 48.
- The failed quotient and codec searches remain scoped negatives. They do not
  refute the full-symbol GAK route that solved `two` or the alternating-mask
  route that solved `one`.
- These small practice groups demonstrate instruments and failure modes. Their
  exhaustive key counts do not transfer to an `{A83, S83}`-scale state group.
