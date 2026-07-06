# Community docs, read firsthand: ingest digest (2026-06-29)

**Status:** provenance + ingest record. Six community Google Docs/Sheets that the
repo had previously catalogued only secondhand (tagged "browser-only / needs
browser") were **read firsthand on 2026-06-29** by fetching the Google
`/export?format=txt` (docs) and `/export?format=csv` (sheets) endpoints and
following the signed redirect — they are link-shared and export cleanly as text,
so the old "does not render to automated fetch" notes were wrong. The seventh
listed resource (Lymm's deck-cipher Discord message) remains unfetchable (Discord
is not exportable); its substance is already in the repo via Lymm's GitHub wiki
(`github.com/Lymm37/eye-messages/wiki`, the GAK campaign in `gak-threads/`).

Each numeric claim below is tagged `[confirmed]` only where it was **recomputed
against the verified corpus** (`src/data/corpus.rs`) this session; community
self-reported numbers are `[community-reported]`; design rationalizations and
numerology are `[speculation]`. **Umbrella caveat:** every per-message statistic
is computed on the canonical *reordered* base-5 trigram stream (values 0–82,
accepted honeycomb order `standard36-u012-d012`). That reading order is
community-inferred, not developer-confirmed, so the whole quantitative block is
"true **under** the accepted reading order," never raw-order fact. (On the raw
stored order these properties — no doubles, the distance-4 spike — do **not**
hold; see `03-confirmed-vs-speculation.md`.)

Sources ingested (firsthand): the doc IDs and one-line provenance now live in
`06-sources.md` / `data/sources.json`. This file is the cryptanalytic digest.

---

## 1. Headline: an eye-message word is the CRC-32 of "lumikki" (Snow White)

Toboter's Progress doc claims: *"One of the byte sequences the eye messages are
stored in (inside the EXE), `0xacf68674`, is the CRC-32b hash of the word
'lumikki', meaning 'snow white'. None of the other byte sequences seem to have
similar properties."*

**Verified this session — with a correction to the variant.** `[confirmed]` (math)
/ `[speculation]` (intent):

- The target value is genuine primary data: `0xacf68674` is the **second u32 of
  eye message 0's first stored pair** `[0x5634505c, 0xacf68674]`
  (`src/data/generator.rs:34`; Xkeeper0's verbatim PHP transcoder
  `data/eye-messages/xk_eye.php:53`). It is half of the 64-bit value
  `0xacf686745634505c` whose base-7 decode is the repo's confirmed worked example.
- Standard CRC-32 ("CRC-32b" in PHP's hashing names) of `lumikki` is
  `0x5bfc21b9` — **does not match**. So the community label is imprecise.
- The match is the **CRC-32/BZIP2** variant (poly `0x04C11DB7`, init/xorout
  `0xffffffff`, **non-reflected**): `CRC-32/BZIP2("lumikki") = 0x7486f6ac`, whose
  byte-reversal is exactly `0xacf68674`. (Reproduce: any CRC-32/BZIP2 of the 7
  ASCII bytes `lumikki`, then read the 4 result bytes little-endian.)
- So the arithmetic is real and reproducible. What is **not** provable is
  authorial *intent*: with ~300 stored u32 words across the 9 messages (150
  `[u32,u32]` pairs in `ENGINE_MESSAGES`, 283 unique nonzero), searched
  against a word list over multiple CRC variants and both byte orders, a single
  spurious "meaningful-word CRC" match is not astronomically unlikely. "lumikki"
  (Finnish for *Snow White*) is a plausible Nolla Easter egg given the studio's
  habits, but plausible ≠ confirmed. Record as: **the value equals
  CRC-32/BZIP2("lumikki") byte-reversed (confirmed); whether that is deliberate is
  unprovable (speculation).**

Recommended follow-up (not done here, separate commit): land this as a
self-checking instrument — a ~15-line in-crate CRC-32/BZIP2 (no new dependency)
plus a unit test asserting `crc32_bzip2(b"lumikki").swap_bytes() == 0xacf68674`
against `generator.rs`'s message-0 pair. That converts a one-shot verification
into a regression-locked capability, per the repo's "instruments, not fixtures"
rule.

---

## 2. CodeWarrior0 "Analytical Overview" — verified quantitative observations

A LANAKI/Friedman-structured walk through the diagnostic ladder
(frequency/IoC → Kasiski → three Kappa tests → cipher-class elimination), using a
known-periodic homophonic sample from Toboter as a **positive control**. It emits
no decode ("To be continued"). Each statistic below was recomputed on the
canonical 0–82 stream:

- **Per-message IoC** `[confirmed]`: `0.958, 1.043, 0.950, 0.918, 1.025, 0.990,
  1.040, 0.872, 0.928`, under the normalization `IoC = 83 · Σ nᵢ(nᵢ−1) /
  [L(L−1)]` (83 = reading-layer alphabet size, so uniform ≈ 1.0). The repo
  previously had only the pooled IoC.
- **Per-message unique-letter counts** `[confirmed]`: `57, 57, 62, 61, 67, 65,
  62, 68, 63`. (Already pinned in `gak-threads/notes/reading-streams.md` — so
  this one is a *confirmation*, not new.)
- **Most-common letters** `[confirmed]`: the set `{5, 13, 54, 60, 66}` is exact
  and unambiguous (counts `5→26`, `{13,60,66}→23`, `54→22`). The doc's listed
  order is not frequency-sorted, but the set matches.
- **Least-common letters** `[community-reported, tie-ambiguous]`: the two strict
  minima `27→3` and `52→5` are confirmed, but "five least-common" is genuinely
  tie-broken — `{0, 7, 12, 53}` all tie at count 6, and the doc's `{0,53,7}`
  silently drops `12`. Record the counts, not a unique "bottom five."
- **"42 blanks"** `[confirmed]`: of the 125 base-5 trigram values, 83 occur and
  42 never do — and the 42 absent are **exactly `83..124`** (the present set is
  literally the contiguous `0..82`, not an interior-gapped subset).
- **Kasiski digraph census** `[confirmed — with an essential qualifier]`: exactly
  **4 digraphs occur 3× and 47 occur 2×**, but *only* under an alignment-aware
  count = number of **distinct within-message column indices**. Under a naive
  pooled-occurrence count it is 37 triples / 59 doubles, and `62 13` actually
  appears 5× raw (collapsing to 3 distinct columns). The four "triples" are
  `62 13` @cols `{4,35,66}`, `63 79` @`{31,83,89}`, `47 17` @`{42,68,102}`,
  `30 71` @`{55,63,81}`. Do not record the bare "4 occur three times" phrasing —
  it is misleading without the column-aligned definition.
- **Positional Kappa decay** `[confirmed]`: superimposing the 9 messages aligned
  at the start, the coincidence rate falls off with start offset — full
  `338/3887` (0.087), from col 25 `76/2987` (0.025), from col 50 `31/2087`
  (0.015). Interpretation (CodeWarrior0): the cipher looks positional over the
  whole length but **not** positional past ~col 50 → "not strictly positional."
  (The doc's per-1000 figures 86/25/14 are loose roundings; true values round to
  87/25/15. The exact fractions match.)
- **Positive control** `[confirmed-as-reported]`: the Kappa tooling, run on
  Toboter's known periodic-homophonic sample, correctly recovered period 83 at
  26/1000 — this is the provenance for the repo's otherwise-unsourced "26/1000 is
  meaningful" threshold, and a clean planted-control validation.
- **Standard-alphabet autokey, tried and failed** `[confirmed-as-reported]`: a
  cursory ciphertext-autokey decode with the identity alphabet and key size 4
  produced a plaintext with no repeats > 2 letters → easy case eliminated.

## 3. CodeWarrior0 — cipher-model mechanics (the original contribution)

These are classical-crypto mechanisms applied to the eyes; tag `[likely]` for the
mechanism, `[speculation]` for the eye-specific application (model-conditional on
ciphertext-autokey):

- **"Base letter" explanation of no-doubles**: in a ciphertext-autokey cipher
  with key offset 1 and a blank at the base letter (plain ordinal 0), no
  ciphertext letter can repeat in a row — a mechanistic account of the repo's
  "no doubles" fact.
- **Running-sum model + the `M+N = E+I` convergence constraint**: the CTAK keystream
  is a running sum of plaintext ordinals; at the "Funny-Looking Obstacle" two
  different plaintexts re-converge iff `M+N = E+I` (equivalently `M−E = I−N`). A
  concrete arithmetic handle on how divergent plaintexts realign — directly feeds
  the repo's non-commutative self-modifying hypothesis. `[speculation]`
- **Distance-4 anomaly = a 4-letter plaintext isomorph**: the ~26 distance-4
  coincidences arise when a frequent 4-letter word has ordinals summing to a
  multiple of the alphabet size. Also reconciles the "distance 4 vs gap 3"
  confusion (some sources count intervening letters). `[likely]`
- **General isomorph theory**: isomorphs appear whenever the keying sequences at
  each repetition differ by a *constant* — true of ciphertext-autokey,
  progressive-alphabet, and clock/Wadsworth devices. This is the theoretical
  backbone of the repo's GAK "perfect isomorph" framing, previously cited only via
  the wiki; CodeWarrior0 is the upstream source. `[confirmed as classical theory]`
- **Cipher-class eliminations by construction**: variable message lengths exclude
  fixed-block ciphers (Playfair, Polybius, square-matrix, Bifid/Trifid);
  small-alphabet systems (VIC, Nihilist, straddling-checkerboard) excluded;
  plaintext-keyed autokey produces *no* isomorphs (so the eyes, which have
  isomorphs, are ciphertext-side); running-key/OTP and rotor machines (Hebern,
  M-138, ENIGMA) "dismissed as unsolvable" without far more text. `[likely]`
- **Author speculations (flagged as such in the doc)**: two or more mixed
  alphabets, "as many as ten"; the initial (indicator) letter sets cipher state,
  perhaps altering only a 4-letter chunk at col 24. `[speculation]`

---

## 4. "Why 83?" — the modulus-design argument

A genuinely valuable structural argument (distinct from anything in the repo):

- **The construction** `[likely as math; speculation as intent]`: 83 is the
  largest *prime* modulus `M < 125` whose maximum value 82 writes as three base-5
  digits that are **distinct, nonzero, and not 4**. The six permutations of
  `{1,2,3}` read in base 5 give `{38,42,58,66,82,86}` → moduli
  `{39,43,59,67,83,87}`; among these 83 is the largest prime (87 = 3·29 is
  composite, "open to factor-based vulnerabilities"). This property is what lets a
  solver recover both the direction→digit legend and the trigram reading order
  **without datamining**.
- **⚠ Do not conflate the two "sixes."** This doc's "6" is six *moduli* from
  permuting `{1,2,3}`. The repo's "6 groups for 83" is the **transitivity
  restriction** — six transitive permutation groups of prime degree 83
  (`{C₈₃, D₁₆₆, C₈₃:C₄₁, AGL(1,83), A₈₃, S₈₃}`,
  `gak-threads/thread-1-dihedral-and-transitivity.md`). Different objects that
  coincidentally both yield 6.
- **Verified structural core** `[confirmed]`: the leading-trigram-digit histogram
  over all 1036 trigrams is `{0:317, 1:312, 2:310, 3:97, 4:0}` (recomputed exact).
  Digit 4 never leads, and a leading 3 spans only values 75–82 (8 of 25), giving
  `25 + 25 + 25 + 8 = 83` distinct values — the real arithmetic of "why 83."
- **Direction names stay a repo convention, not an asserted labeling**: the doc
  reads the histogram as Center 317 / Up 312 / Right 310 / Down 97 / Left 0. The
  *numbers* verify, and the digit↔direction legend is binary-verifiable
  **[Lymm, maintainer-confirmed 2026-07-06]** (eye sprites are hardcoded in the
  drawing function) rather than unverifiable — but per repo policy
  (`src/core/glyph.rs`) digits 0–4 still carry no asserted pixel-direction
  names, since the labeling is a convention no statistic depends on, not an
  unknown being protected.
- **Refinements**: a `~10⁻³³` figure for the 83 present values being
  *specifically* the contiguous `0..82` block (beyond the repo's
  `(83/125)^1036 ≈ 5.836e-185`); and an **order-vs-legend** distinction — the doc
  agrees the direction legend is datamined but argues the trigram *reading order*
  is not datamine-able and is instead structurally recoverable. The repo doesn't
  currently make that distinction; worth recording as a refinement.

---

## 5. Toboter Progress — granular micro-observations

All `[community-reported]` and reading-order-conditional unless noted; several are
directly testable against `corpus.rs` (flagged ✓-testable) and are good candidates
for a future verification pass:

- CRC-32("lumikki") = `0xacf68674` — see §1 (the one verified here).
- All starting trigrams are **> 26** (Työskentely Juho). ✓-testable; relates to
  `findings/base5-first-trigram.md`.
- Three messages (E1/E3/E5) have trigram sums of `abab` shape in base 10
  (4040/5656/4545) (SaltyOutcome). ✓-testable.
- No eye-message trigram sum has a two-digit prime factor (~0.4% by chance,
  Toboter). ✓-testable.
- For all messages except West 4, the first eye is one greater than the second
  eye of the following message in internal order (Dr Cats). ✓-testable.
- No first-two-trigrams of any message have GCD 1 (~6.5%; ~60% if first trigram
  can't be prime) (Naugam). ✓-testable.
- Gap-distance repetition histogram: gap 0 = none, gap 1 = 5, gap 3 = 26 — i.e.
  the **only missing gap size is 1** (load-bearing: it rules out `(char + N·pos)
  mod 83`, which always leaves multiple missing gap sizes). `[likely]`
- Messages have 16 "trigrams with no trigram that only occurs after them" vs an
  expected ~8 (Toboter).
- Some messages have prime trigram-length → no fixed-length partition is possible
  (Toboter). `[likely]`
- **State lower bound (upstream of the repo's "~83 states")**: the state must have
  ≥ **21** values, with 10% chance it exceeds 26 (Toboter) — note these differ
  from the wiki's "~88 → 83" figure the repo records; reconcile, don't merge.
- **Ruled-out modular forms** (all `[likely]` as eliminations): `c = (m·p + s·x)
  mod 83` forces the unique `m=25, s=51`; `c = (p + f) mod 83` needs alphabet ≥69,
  `c = (p · f) mod 83` ≥61; `c = c₋₁ + a·b^p mod 83` reduces nothing.
- **Lymm's pattern strings**: `a_b_cb_ac` appears 6× in the first three messages,
  4 of which extend to `x_____ayb_cb_ac_yx`; another `ab_c____b_ac` in the last
  three. Inference: the same letter appears three times in a row → spaces are
  likely omitted from the plaintext. `[speculation]`
- Specific isomorphs that **never** chain successfully (e.g.
  `AB......A.C.D.BD.CB`) — concrete imperfect-isomorph evidence for the repo's
  isoscan/perfectiso work. `[speculation/structural]`

## 6. Dead-end catalog (tried and failed — `[confirmed as attempted]`)

From Toboter's "attempted approaches" list, the entries not already in the repo:
stereographic ciphers; colouring eyes by look-direction; overlapping all 9 worlds'
same-direction eyes; submerging eyes in common liquids; line-drawing in eye
directions; Emerald-Tablet word-frequency mapping; trigrams as offsets into
tablet/book/orb-room texts; brute-force add/subtract of messages; Kantele-note
music (by order, by pitch, by trigram-sum); ASCII offset 33/32, Hex, Octal;
trigrams mod 26 → letters; first-glyph-as-line-number; desert-ruins hint; Capybar
diamond cipher. (Useful as a "don't re-run these" ledger.)

## 7. Numerology quarantine (`[speculation]` — recorded, not endorsed)

The "83 Occurrences" doc (the one the maintainer labeled "83 & 23 / Luc") and the
tail of "Why 83?" are coincidence catalogs. None rise above numerology except the
single structural line "83 distinct trigram values" (already confirmed). For the
record, the catalog: 83 liquids; 83 gun names; 83% modifier-card chance
(`Random(0,100) < 83`); Kolmi health `1660 = 20·83`; 83×26 blood pool; blood
`#830000` / `aa830000` wang colors; "83 'you'" and "83 sentences" in wall
messages; blurhash is base-83; 83-char Erasure-"Always" snippet; 83 wiki material
subcategories; quadratic-residues-mod-83 "= 42"; water biome at chunk `(60,22)`,
`60+22=82`, both primitive roots mod 83; "3 in-game 26-letter alphabets ≈ 83";
Kolmisilmä "8 holes, 3 eyes → 83"; earthquake-circle ring has 84 ones in binary;
PAM-5 "eye pattern" pun. Keep quarantined; do not promote to the structural body.

## 8. Contradictions & corrections

- **Arvi developer statement — RESOLVED, and the repo's "no dev ever commented
  on the eyes" claim is now corrected** `[confirmed statement exists; relayed]`.
  Toboter's doc relays (via FuryForged) that Arvi confirmed the eyes contain a
  message. The maintainer then supplied the full verbatim transcription and the
  **primary video** (`youtube.com/watch?v=ItzQh6K3hP8`, the 2021-10-15 FuryForged
  Noita-dev stream; Discord permalink
  `discord.com/channels/453998283174576133/817530812454010910/899514286290898985`,
  posted 2021-10-17), confirming the two are the same quote. Arvi, verbatim:
  *"for the eye decorations… I have confirmation that the eye decorations do
  contain a message… They actually do have a meaning"*; asked how solvable
  (1–10), ~*"square root of minus 1… probably very difficult."* Two notable
  points: (1) this is the **same video** the repo had already catalogued under
  "Roguelike Celebration / transcript not retrievable" (`facts.json` Arvi
  entry) — the eye quote was in it all along, un-fetchable by automated tools,
  the *same* browser-only pattern as the Google Docs in this ingest; (2) it
  asserts **meaning/intent**, not **solvability** (Arvi disclosed no method and
  implied near-impossible difficulty), so the unsolved status and the
  solvability-to-plaintext caveat are unchanged. **Canonical docs corrected**
  (`01-overview.md`, `02-theories-and-encoding.md`, `03-confirmed-vs-speculation.md`,
  `facts.json`): the blanket "no developer has ever commented on the eyes" is
  replaced with "one eye-specific dev statement exists (meaning + difficulty, no
  method)"; the narrower, still-true "no dev confirmed *solvability/decodability*"
  claims (`facts.json` ~250/360/787) are left intact.
- **Toboter doc date** — corrected in `sources.json`/`06-sources.md` from the
  stale "2024-01-25" to the live header "28.12.2025."
- **Emerald Tablet "holds raw data"** — corrected: it is a link directory (§ in
  `06-sources.md`).
- **Alphabet-chaining "succeeded"** `[disputed vs repo analysis]`: the doc carries
  a later note *"Update: The isomorphs of the first three messages have been
  chained successfully (Toboter)"* — stronger than the repo's "not completely
  successful." This is community-self-reported and does not displace the repo's
  GAK chaining-conflict analysis; flag as an unreconciled community update.
- **`(66,5)` precision**: the repo's loose phrasing "all nine messages share the
  same first two trigrams [66,5]" (`02-theories-and-encoding.md`) is imprecise —
  the first trigram *differs* across all nine; `(66,5)` are the **2nd–3rd**
  trigrams. Worth tightening that one line.

## 9. Leads worth chasing (uncatalogued, surfaced by the link hubs)

Ranked, from the Emerald Tablet directory + defektu's tools doc:

1. **Datamined generation function ported to C++ and to JS** (2022-12-11) —
   independent re-implementations of the engine math; exactly the independent
   cross-check the repo's "binary-RE step is single-upstream/thin" note asks for.
2. **"Raw Eye Messages Data" (2021-02-06) + Nemare's decimal "Eye Values"** —
   independent early raw transcriptions to cross-validate the corpus against
   ngraham20 / SirCapybar / ToboterXP.
3. **RmVw — "Eyes – Vigenère Theory" (2021-03-14)** — a dedicated primary doc on
   the Vigenère hypothesis; not anywhere in `research/`.
4. **7Soldier — per-message frequency analysis (2025-04-06)** — the newest
   substantive cryptanalysis doc by ~4 years; most likely to contain unseen
   findings.
5. **CodeWarrior0 — "Isomorphism in Classical Ciphers" (2022-03-31)** — a curated
   menu of isomorphism-bearing ciphers; a ready hypothesis list for the repo's
   isoscan/perfectiso instruments. (Plus new analysis-code repos: ZeroPoint's
   LymmPatternScanner, Joanie's NoitaEyeCipherTools, tomster12's Eye Web Analyzer.)

## 10. The "83 & 23" resolution

The resource the maintainer described as "interesting 83 & 23 connection found by
Luc" is the doc titled **"83 Occurrences"** (ID `1lrPl…`). Read firsthand: the
string "23" never appears, nor does any author "Luc"; the only numbers it pairs
with 83 are **26** (the `83×26` blood pool) and **20** (`1660 = 20·83`). There is
**no 83↔23 connection** in it — the label is a mismatch, most likely a slip for 26
or 20. (Flagged back to the maintainer.)
