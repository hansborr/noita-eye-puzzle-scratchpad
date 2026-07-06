# Practice `two` shadowfinish + substitution solve

Status: **maintainer-confirmed plaintext, not an original-generator round-trip**
(2026-07-06).

## Post-confirmation status

The maintainer confirmed the frozen practice `two` solution after the candidate
record and blind confirmation packet were committed. This upgrades the
`shadowfinish` + `substfinish` result from a strong hypothesis to a
ground-truth-confirmed practice-puzzle solve.

Scope of the confirmation:

- The code-driven recovery is the `shadowfinish` candidate plus the
  `substfinish` letter-level monoalphabetic finish below.
- The punctuation, hyphenation, quotes, and the repaired opening `Would` are a
  source/syntax-aligned restoration over that letter-level result.
- No Rust code recovered punctuation or consulted the public Octal article as a
  scoring source. The public-source alignment was a human/external restoration
  step after the computational candidate already existed.
- This is still not an original-generator round-trip; see
  `research/findings/two-original-generator-roundtrip-blocker.md`.

## What changed

The fixed `shadowfinish` discriminator produced a candidate record:

- `research/gak-threads/candidates/shadowfinish-two-shadowfinish-seed-736861646f776603.md`
- shadowfinish verdict: `Candidate`
- conditional matched null: `null_ge 0/49`, `p_emp 0.0200`
- caveat: the null is over retained max-soft shadowsearch classes only; the
  phase-0 round-trip is vacuous on the co-searched table/permutation/order
  surface.

The raw candidate looked like mixed-case gibberish, but it used exactly 26
non-space symbols. The new `substfinish` instrument treated those symbols as a
monoalphabetic layer with visible spaces preserved.

## Reproducible second-stage run

```sh
awk '/^```text$/{flag=1;next}/^```$/{flag=0}flag' \
  research/gak-threads/candidates/shadowfinish-two-shadowfinish-seed-736861646f776603.md |
  cargo run --release -q -- substfinish --stdin \
    --alphabet 'ABEGLPUXabcdefghiklmnopxyz' \
    --restarts 24 --iters 12000 --null-trials 20 \
    --seed 0x7375627374697401
```

`substfinish` passed its planted-positive and flat-control self-test before real
input. On the real candidate it reported:

- input: 298 symbols, 26 alphabet entries, 51 separators
- matched null: space-position-preserving symbol shuffles
- score: observed `-10.9065`, null max `-12.5743`
- `null_ge 0/20`, `p_emp 0.0476`
- margin vs null max: `1.6678`
- verdict: `Candidate`

## Reading

The second-stage render begins with a malformed first word, then the
octal-system question:

```text
_OULD AN OCTAL NUMBER SQSTEM HAVE COME BEFORE THE DECIMAL NUMBER SQSTEMZ ...
```

The remaining bad letters are expected under the current finisher because it
forces all non-space symbols to letters. Source/syntax alignment gives this
best-effort plaintext:

```text
Would an octal number system have come before the decimal number system? It has been suggested that the reconstructed Proto-Indo-European word for "nine" might be related to the Proto-Indo-European word for "new". Based on this, some have speculated that proto-Indo-Europeans used an octal number system, though the evidence supporting this is slim.
```

Source alignment points to a short question about an octal number system
predating decimal, followed by the Octal article's "By Europeans" content about
the Proto-Indo-European `nine`/`new` speculation and weak evidence:

<https://en.wikipedia.org/wiki/Octal#By_Europeans>

Stable source snapshots checked:

- <https://en.wikipedia.org/w/index.php?title=Octal&oldid=1361717197#By_Europeans>
  (2026-06-29)
- <https://en.wikipedia.org/w/index.php?title=Octal&oldid=1033968504#By_Europeans>
  (2021-07-16)

The aligned wording is therefore an octal-system / decimal-system question plus
the Octal article's `nine`/`new` sentence. It is not an exact byte-for-byte copy
of the checked public source: the candidate adds the opening question, omits the
current article's parenthetical `(PIE)`, and expands the article's second `PIE`
reference to `Proto-Indo-European`.

Uncertainty notes:

- `Would` repairs the observed malformed first word; the monoalphabetic layer
  itself certifies only `_ould` and the surrounding question grammar.
- The question mark, period after `"new"`, commas after `this` and the second
  `system`, final period, quotes, and hyphens are source/syntax-aligned
  restoration, not recovered by `substfinish`.
- A direct raw-symbol to punctuated-character map would not be one-to-one, so
  this is a best-effort plaintext restoration over a letter-only candidate rather
  than a recovered punctuation alphabet.

## Claim ceiling

This should be treated as **practice `two` solved at the plaintext level and
confirmed by the maintainer against withheld ground truth**. We still lack an
independent round-trip through the original puzzle generator, and the shadowfinish
null does not replay stage-(ii) survivor selection over all 104,096 candidates.

The punctuation/source alignment is a human/external restoration aid. It helped
produce the readable final sentence form, but it is not part of the code's
cryptanalytic scoring surface and should not be cited as the "pure" recovered
layer.

The next useful work is narrow:

- add a punctuation-capable finishing mode only if we want to measure how much of
  the punctuation can be recovered without public-source alignment;
- run a broader stage-(ii)-replaying null only if we want a pipeline-level
  statistical claim;
- build an original-generator verifier only if the missing generator/key/codec
  artifacts become available.
