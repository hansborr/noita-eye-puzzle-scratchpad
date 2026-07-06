# Practice `two` original-generator round-trip blocker

Status: **blocked by missing external generator/key/codec data** (2026-07-06).

Scope: this audit covers only the frozen `shadowfinish` plus `substfinish`
candidate recorded in
`research/gak-threads/candidates/shadowfinish-two-shadowfinish-seed-736861646f776603.md`
and summarized in
`research/findings/two-shadowfinish-substitution-candidate.md`. No broader search
was run, and the candidate text was not changed.

## Feasibility result

The repo does **not** currently contain enough information to re-encode the
proposed plaintext through the original practice-puzzle generator and compare it
byte-for-byte against `research/data/practice-puzzles/two`.

Building a "round-trip verifier" from the committed `shadowfinish` data alone
would be misleading. It would only replay the already-fitted order-48 shadow
quotient and the co-searched table/permutation/order used to derive the candidate,
not the original puzzle generator.

## What is present

- The exact ciphertext fixture: 698 symbols over `A..L` in
  `research/data/practice-puzzles/two`.
- A repo-verified order-48 shadow closure from raw isomorph column maps, plus the
  `shadowsearch` machinery that can regenerate quotient q-pattern survivors from
  the ciphertext.
- The retained `shadowfinish` candidate metadata: class `9`, phase `phase0`,
  table `sixbit-lower-space`, digit order `HL`, and label-to-digit permutation
  `[1, 5, 3, 7, 4, 0, 2, 6]`.
- The `substfinish` second-stage monoalphabetic hypothesis, which makes the
  candidate read like an octal-system / Proto-Indo-European English passage but
  treats every non-space symbol as a letter.

## What is missing

An original-generator round-trip needs all of the following, none of which is
committed here for practice puzzle `two`:

- **Exact plaintext byte stream and normalization.** The current readable text is
  a hypothesis plus source alignment, not an exact frozen plaintext. The
  `substfinish` layer cannot certify punctuation, hyphens, quotes, sentence
  boundaries, capitalization, or whether spaces/punctuation were encoded,
  normalized, or dropped by the original generator.
- **Original plaintext codec.** The `shadowfinish` table, digit order, and
  label-to-digit permutation are selected from the attack surface. They explain
  one quotient readout but are not author-provided codec parameters.
- **Original GAK generator/key.** The repo has a regenerated order-48 shadow and
  representative quotient keys, while the cross-agent record reports a true
  order-96 group. The original group, hidden subgroup/readout convention,
  composition convention, initial state, and plaintext-symbol-to-group-element
  mapping are not present.
- **A source-generator artifact.** No committed script, seed, key file, or
  maintainer solution record exists that would take the proposed plaintext and
  emit the exact 698-symbol ciphertext under the original construction.

## Why the current shadowfinish round-trip is vacuous

`shadowfinish` first derives a q-pattern from the ciphertext through
`shadowsearch`, then enumerates bijective interpretations of that same q-pattern.
For a phase-0 candidate, the replay check:

1. decodes the candidate plaintext back to canonical q symbols using the same
   candidate table, digit order, and label-to-digit permutation;
2. maps the canonical q symbols back through the candidate's retained class
   representative; and
3. replays those q symbols through the representative order-48 shadow key.

Because the codec knobs are co-searched and bijective on the retained surface,
every in-range phase-0 interpretation can re-encode to the observed ciphertext by
construction. The check is still useful as an implementation invariant, but it is
not evidence that the plaintext, punctuation, codec, or original generator key is
correct.

## Minimal data that would close the blocker

Any one complete source of external truth would be enough to build a real
file-driven verifier:

- the original generator implementation plus the exact key/config/seed needed for
  puzzle `two`;
- or a maintainer/author solution record containing the exact plaintext
  normalization, codec table/digitization, initial state, group/readout
  convention, and plaintext-symbol transition mapping;
- or an equivalent artifact that deterministically maps the exact proposed
  plaintext bytes to the 698 emitted symbols.

With that data, the next change should be a small file-driven verifier/test that
reads the plaintext and generator parameters from files and asserts that the
encoded output exactly equals `research/data/practice-puzzles/two`.
