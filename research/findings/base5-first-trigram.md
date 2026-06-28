# First-trigram "message starts": the base-5 question, answered

**Status:** computed result, regression-locked. Every number below is produced in
code from the verified corpus (`src/data/corpus.rs`) by
`src/analysis/first_trigram.rs` and asserted in `tests/first_trigram.rs`. Nothing
here is hand-transcribed.

## The question

The wiki's [Message Starts] page notes that the first trigram of every eye
message is different, then lists candidate explanations (a 1-9 / A-I index, a
checksum, "the last character moved to the front") and adds:

> There are also some interesting observations about the base 5 values of these
> first trigrams, which might be a hint for some reason that base 5 was used, but
> we haven't figured anything out yet.

This note tabulates the nine first trigrams and tests those hypotheses.

## Two representations (do not conflate them)

A "first trigram" has two different numeric values, and they disagree:

- **[A] Storage-order base-5 form** — the first three stored orientation digits
  grouped as a trigram, value `first*25 + second*5 + third`, range `0..=124`.
  This is the raw engine-storage chunking.
- **[B] Honeycomb reading-layer value** — the first trigram emitted by the
  accepted honeycomb reading order (`standard36-u012-d012`), range `0..=82`. This
  is the symbol the community actually reads.

They differ because the honeycomb walk groups a different triple of eyes than
three consecutive stored digits. (Concretely: the first two digits agree in all
nine messages; only the third eye differs — storage takes row 0 column 2, the
honeycomb takes row 1 column 0.)

## The table (computed)

| id | msg   | [A] digits | [A] value (0-124) | [A] value mod 5 | [B] value (0-82) | [B] digits |
|----|-------|-----------|-------------------|-----------------|------------------|-----------|
| 0  | east1 | 201       | 51                | 1               | 50               | 200       |
| 1  | west1 | 311       | 81                | 1               | 80               | 310       |
| 2  | east2 | 121       | 36                | 1               | 36               | 121       |
| 3  | west2 | 301       | 76                | 1               | 76               | 301       |
| 4  | east3 | 221       | 61                | 1               | 63               | 223       |
| 5  | west3 | 111       | 31                | 1               | 34               | 114       |
| 6  | east4 | 101       | 26                | 1               | 27               | 102       |
| 7  | west4 | 301       | 76                | 1               | 77               | 302       |
| 8  | east5 | 111       | 31                | 1               | 33               | 113       |

Per-position base-5 digit sets across the nine messages:

| position | [A] storage | [B] reading |
|----------|-------------|-------------|
| leading (×25) | {1,2,3} | {1,2,3} |
| middle (×5)   | {0,1,2} | {0,1,2} |
| units (×1)    | **{1}** | {0,1,2,3,4} |

## Hypothesis verdicts

Numerical index (1-9, 0-8, or A-I): rejected. Neither representation is a
permutation of a contiguous nine-value index.
- [A] storage values span 26-81 and even contain duplicates (76 appears for
  west2 and west4; 31 for west3 and east5) — only 7 distinct values.
- [B] reading values are all distinct, but span 27-80 — far from 1-9 / 0-8, and
  sorting them does not recover message order, so they are not even a monotone
  relabeling of the message id.

Checksum / "last character moved to the front": rejected. Computed against
the full trigram sequences, none of the following holds for the nine messages,
in either layer: `first == last`; `first == sum(body) mod M`;
`first == sum(all) mod M`; `first == XOR(body)` (M = 125 for [A], 83 for [B]).
The first trigram is not a copy of the last trigram and is not a simple
sum/XOR checksum of the body. (Note: a true "last char rotation" of the
*plaintext* is not directly falsifiable without plaintext; its simplest
ciphertext signature, `first == last`, is absent.)

Base-5 digit structure: one real regularity, the rest weak. See below.

## Robust observations (with n = 9 honesty)

1. **Distinctness is a reading-layer property, not a base-5-form property.** The
   wiki's "the first trigram value in every message is different" is true for the
   reading layer [B] (9 distinct values) but false for the raw base-5 storage
   form [A], where 76 and 31 each occur twice. So when discussing "the base 5
   values of the first trigrams," it matters which value you mean: the
   raw base-5 forms collide.

2. **Every storage-order first trigram ends in base-5 digit 1** (equivalently,
   all nine [A] values are `≡ 1 (mod 5)`). This is the cleanest pattern, but read
   it carefully:
   - It is specific to the first trigram. Over all 1036 storage trigrams the
     units digit is not concentrated on 1 — histogram `[263, 254, 238, 163, 118]`
     for digits 0-4 (itself skewed, peaking at digit 0), so digit 1 is only
     ~24.5% corpus-wide, not ~100%.
   - A naive uniform-random null gives `P = (1/5)^9 ≈ 5e-7`, which *looks*
     decisive — but the nine messages are not independent: they share large
     sections right after the start. The constant units digit is exactly "the
     third rendered eye is identical (=1) across all messages," i.e. the leading
     edge of the documented [shared sections], not an independent numeric law.
     The naive p-value therefore massively overstates the surprise.

3. **Both layers restrict the leading digit to {1,2,3} and the middle digit to
   {0,1,2}.** Partly an artifact, partly weak signal:
   - Leading digit `4` is *impossible* for any value `≤ 82`, so "no leading 4" in
     [B] is just the 83-symbol alphabet bound, not a finding.
   - "No leading 0" (all values `≥ 25`) and "no middle 3 or 4" are reachable but
     unobserved — with n = 9 this is low-power and not significant on its own.

## Does this explain "why base 5"?

No. The only base-5-flavoured regularity (observation 2) reduces to a single
shared constant eye, and the distinctness that motivates the "index" reading
lives in the honeycomb layer, not the base-5 digits. We find no evidence that the
first-trigram base-5 values are a hint for the choice of base 5. The honest
summary is: the index, checksum, and last-char-to-front theories are
unsupported; the first trigram is a genuinely variable per-message prefix sitting
in front of shared body content, and its only sharp regularity is inherited from
that shared content.

## Reproduce

- Analysis module: `src/analysis/first_trigram.rs` (`first_trigram::analyze()`,
  plus `IndexVerdict`, `ChecksumVerdict`, `DigitPositionSets`, and a
  `Report::render()` table).
- Regression-locked tests: `tests/first_trigram.rs` (`cargo test --test
  first_trigram`).

[Message Starts]: https://github.com/Lymm37/eye-messages/wiki/Message-Starts
[shared sections]: https://github.com/Lymm37/eye-messages/wiki/Shared-Sections
