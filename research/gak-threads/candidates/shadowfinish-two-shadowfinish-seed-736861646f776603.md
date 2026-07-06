# Shadowfinish candidate: two-shadowfinish

Stable label: label=two-shadowfinish seed=0x736861646f776603

## Verdict

**Candidate — logged as a HYPOTHESIS, not a verified decode.**

Round-trip invariant satisfied: true. vacuous phase-0 replay invariant on the co-searched bijective table/permutation/order surface; every in-range phase-0 interpretation re-encodes through the representative shadow key, so this is not plaintext evidence
Matched-null p_emp: 0.020000 (null_ge 0/49)
Matched-null scope: decoy q-pattern label shuffles of the artifact's retained max-soft shadowsearch classes; does not replay stage-ii survivor or non-max selection
Surface: 13547520 interpretations; Tier-A retained 12288; top-K dropped 12638112

## Candidate Metadata

- class: 9
- table: sixbit-lower-space
- phase: phase0
- digit order: HL
- permutation: [1, 5, 3, 7, 4, 0, 2, 6]
- combined score: -1.813639
- quadgram score: -13.973309
- word score: -6.263653
- anchor score: -5.297561

## Candidate cleartext (verbatim; hypothesis)

```text
mEiBd bA EelbB Aiyfan mPmlay xbka eEya facEna lxa daezybB Aiyfan mPmlayU Xl xbm faaA miggamlad lxbl lxa naeEAmlnielad pnElEyXAdEyGinEhabA oEnd cEn fAzAaf yzgxl fa naBblad lE lxa pnElEyXAdEyGinEhabA oEnd cEn fAaofA Lbmad EA lxzmB mEya xbka mhaeiBblad lxbl pnElEyXAdEyGinEhabAm imad bA EelbB Aiyfan mPmlayB lxEigx lxa akzdaAea mihhEnlzAg lxzm zm mBzyA
```

## Secondary monoalphabetic finish (2026-07-06)

Instrument: `substfinish` (`src/attack/substitution.rs`), added after this
candidate surfaced so the follow-up is reusable rather than a scratch script.

Observation: the candidate contains exactly 26 non-space symbols
(`ABEGLPUXabcdefghiklmnopxyz`). Treating the visible spaces as word separators and
running a monoalphabetic substitution search produces a readable English
hypothesis. The run is gated against space-position-preserving shuffles of the
same symbol stream.

Reproduce:

```sh
awk '/^```text$/{flag=1;next}/^```$/{flag=0}flag' \
  research/gak-threads/candidates/shadowfinish-two-shadowfinish-seed-736861646f776603.md |
  cargo run --release -q -- substfinish --stdin \
    --alphabet 'ABEGLPUXabcdefghiklmnopxyz' \
    --restarts 24 --iters 12000 --null-trials 20 \
    --seed 0x7375627374697401
```

Result:

- `substfinish` self-test: PASS (planted positive exact; flat matched control
  rejected).
- Candidate score: `observed -10.9065`; matched null: `null_ge 0/20`,
  `p_emp 0.0476`, margin vs null max `1.6678`.
- Rendered candidate preview:

  ```text
  SOULD AN OCTAL NUMBER SQSTEM HAVE COME BEFORE THE DECIMAL NUMBER SQSTEMZ YT HAS BEEN SUGGESTED THAT THE RECONSTRUCTED WROTOMYNDOMJUROPEAN KORD FOR BNINEB MIGHT BE RELATED TO THE WR...
  ```

Interpretation:

- This is strong forward progress: the shadowfinish output is not arbitrary
  gibberish; it is an English-shaped monoalphabetic layer with spaces already
  mostly placed.
- It is not a clean final decode. The current `substfinish` scorer maps every
  non-space symbol to `A..Z`, so punctuation, hyphens, quotes, and sentence
  boundary marks are forced into letters. That explains artifacts such as
  `SQSTEMZ` and `WROTOMYNDOMJUROPEAN`.
- Source alignment identifies the content as a short question about whether an
  octal system could/would predate decimal, followed by the Octal article's
  "By Europeans" note about Proto-Indo-European `nine`/`new` speculation and
  weak evidence. The aligned public source is
  <https://en.wikipedia.org/wiki/Octal#By_Europeans>.

## Punctuation/source-aligned reading (2026-07-06)

Best-effort plaintext with punctuation and hyphenation:

```text
Would an octal number system have come before the decimal number system? It has been suggested that the reconstructed Proto-Indo-European word for "nine" might be related to the Proto-Indo-European word for "new". Based on this, some have speculated that proto-Indo-Europeans used an octal number system, though the evidence supporting this is slim.
```

Source alignment:

- Article source: Wikipedia, Octal, "By Europeans":
  <https://en.wikipedia.org/wiki/Octal#By_Europeans>.
- Stable source snapshots checked:
  <https://en.wikipedia.org/w/index.php?title=Octal&oldid=1361717197#By_Europeans>
  (2026-06-29) and
  <https://en.wikipedia.org/w/index.php?title=Octal&oldid=1033968504#By_Europeans>
  (2021-07-16).
- The article source supplies the `nine`/`new`, octal-system, and weak-evidence
  content, plus the hyphenation style for `Proto-Indo-European` and
  `proto-Indo-Europeans`.
- No checked public Octal revision is an exact byte-for-byte source for the whole
  candidate: the candidate adds the opening question, omits the current article's
  parenthetical `(PIE)`, and expands the article's second `PIE` reference to
  `Proto-Indo-European`.

Uncertainty notes:

- The opening `Would` is an editorial repair of the `substfinish` render `SOULD`;
  the monoalphabetic layer certifies only `_ould` plus the surrounding question
  shape.
- The question mark after the first `system`, the period after `"new"`, the comma
  after `this`, the comma after the second `system`, and the final period are
  source/syntax-aligned punctuation, not independently recovered cipher symbols.
- A direct raw-symbol to punctuated-character map is not one-to-one: several raw
  symbols would have to serve both a letter and punctuation/case. Treat this as a
  source-aligned plaintext restoration over the letter-only candidate, not as a
  recovered punctuation alphabet.

Claim ceiling:

**Strong plaintext hypothesis, not a verified decode.** The phase-0 round-trip is
still the vacuous shadowfinish invariant, the matched null remains conditional on
the retained shadowsearch classes, and the source alignment is a human/external
confirmation aid rather than an independent cipher gate. The aligned text above is
the current best-effort reading for practice `two`, but it is not maintainer
ground truth and not an original-generator round-trip.
