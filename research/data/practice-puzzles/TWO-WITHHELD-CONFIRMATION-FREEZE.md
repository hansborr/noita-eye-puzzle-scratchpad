# Practice `two` withheld-ground-truth confirmation freeze packet

Status: **frozen candidate packet for blind maintainer comparison, not a
confirmation** (2026-07-06).

This packet packages the already-logged practice `two` candidate for a
withheld-ground-truth check. No private or withheld file was searched or read for
this packet, and the candidate record below was not edited.

## Frozen candidate record

- Candidate record:
  `research/gak-threads/candidates/shadowfinish-two-shadowfinish-seed-736861646f776603.md`
- SHA-256:
  `eca855c902e0ae4a9079bca64bef08fec60de03ca00e56b1e8333b4a1968fb85`

Hash command:

```sh
sha256sum research/gak-threads/candidates/shadowfinish-two-shadowfinish-seed-736861646f776603.md
```

Observed output:

```text
eca855c902e0ae4a9079bca64bef08fec60de03ca00e56b1e8333b4a1968fb85  research/gak-threads/candidates/shadowfinish-two-shadowfinish-seed-736861646f776603.md
```

## Reproduced `substfinish` run

Command:

```sh
awk '/^```text$/{flag=1;next}/^```$/{flag=0}flag' \
  research/gak-threads/candidates/shadowfinish-two-shadowfinish-seed-736861646f776603.md |
  cargo run --release -q -- substfinish --stdin \
    --alphabet 'ABEGLPUXabcdefghiklmnopxyz' \
    --restarts 24 --iters 12000 --null-trials 20 \
    --seed 0x7375627374697401
```

Observed output summary from a fresh run on this branch:

- self-test: `PASS` (planted positive exact; flat matched control rejected)
- input: 298 symbols, 26 alphabet entries, 51 separators
- search: 24 restarts, 12000 iterations, seed `0x7375627374697401`
- matched null: space-position-preserving symbol shuffles; 20 trials
- score: observed `-10.9065`; `null_ge 0`; `p_emp 0.0476`; margin vs null max
  `1.6678`
- verdict: `Candidate`
- candidate preview: the octal-number-system question and
  Proto-Indo-European `nine` / `new` passage already recorded in the frozen
  candidate record

Important ceiling: the render is produced by the current letter-only finisher. It
is expected to force punctuation, hyphens, quotes, and sentence marks into
letters, so it is not an exact punctuation claim.

## Proposed blind comparison protocol

1. Verify the frozen candidate record hash above before looking at withheld
   ground truth.
2. Re-run the exact `substfinish` command above, or compare against the frozen
   command/output summary and candidate record.
3. Only the maintainer holding the withheld practice `two` cleartext should open
   or inspect that cleartext. Do not share the withheld text with agents and do
   not commit it during this check.
4. Compare the withheld cleartext to the frozen candidate without changing the
   command, seed, alphabet, mapping, scorer, or candidate record.
5. Record only a minimal verdict first: `PASS-content`, `PASS-exact`, `FAIL`, or
   `INDETERMINATE`. Any later exact-match regression should be a separate,
   explicit maintainer-approved step.

## Pass / fail criteria

- `PASS-exact`: the withheld cleartext matches a normalized exact candidate
  string under a predeclared normalizer. This packet does not assert that level;
  punctuation-aware finishing may be needed before making an exact-string claim.
- `PASS-content`: the withheld cleartext is the same passage in the same order:
  a question about whether an octal number system came before decimal, followed
  by the Proto-Indo-European `nine` / `new` speculation and the statement that
  evidence for Proto-Indo-European octal use is slim. Case, punctuation,
  hyphenation, quotes, and the known first-word residual uncertainty do not decide
  this weaker content criterion.
- `FAIL`: the withheld cleartext is materially different, lacks that ordered
  three-part content, or only shares generic number-system / octal vocabulary.
- `INDETERMINATE`: the withheld cleartext partially overlaps but not enough to
  call a content pass without exposing more ground truth. Record only the
  mismatch class unless the maintainer explicitly chooses to publish more.

## Maintainer request text

Please compare the frozen practice `two` candidate
`research/gak-threads/candidates/shadowfinish-two-shadowfinish-seed-736861646f776603.md`
at SHA-256
`eca855c902e0ae4a9079bca64bef08fec60de03ca00e56b1e8333b4a1968fb85`
against the withheld cleartext, without sharing or committing the withheld text.
Report only `PASS-content`, `PASS-exact`, `FAIL`, or `INDETERMINATE` plus any
non-sensitive mismatch class. This packet makes no confirmation claim.
