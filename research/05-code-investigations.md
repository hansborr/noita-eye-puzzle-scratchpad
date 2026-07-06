# 05 — Code Investigations: the skeptical experiment surface

This document is the current map of the skeptical experiments that test the
community's claims about the Noita "Eye Messages" puzzle. It is organized as a
standing surface, not a to-do list: for each experiment it states what the
experiment tests, how a *null* result reads, and where the code that runs it now
lives (or that it remains open). The guiding principle is unchanged — do not
assume the community is right. Every experiment is built so that a *null* result
is as informative as a positive one, and several exist specifically to detect
whether an apparent "encoding" is a coincidence or a side effect of the
generation pipeline.

Most of the null/control battery these experiments call for is now built in the
crate and runnable as CLI subcommands (`cargo run -- <cmd>`); the genuine
remaining open items are external (a vendored byte-for-byte cross-seed
transcription diff, and any external anchor for the eyes — key material (the
letter→action assignment), a method/cipher-family disclosure, or known
plaintext; there is no fixed symbol-to-meaning table to find, since the cipher
is polyalphabetic). Line numbers rot, so code below is cited by module path and
subcommand name rather than file:line.

A recurring methodological trap runs through almost all community work and must
be confronted head-on: nearly every "cipher property" (flat frequency, no
doubled symbols, distance-4 anomaly, contiguous 0–82 range) is conditional on a
chosen reading order that was itself selected *because* it produced a
clean-looking result. Independent verification on this investigation found that
on the raw stored order, those properties largely vanish (17 adjacent-equal
trigrams exist; distance-4 is not elevated; the value set is 0–122 with gaps, not
0–82) [confirmed]. So the single most important class of experiments here is the
one that quantifies how much of the "signal" survives correction for the
multiple-comparisons / order-selection problem.

---

## Data sources (ground-truth substrate)

Before any experiment, obtain and cross-validate the raw glyph data. Do not trust
a single transcription. There are at least four independent transcriptions; diff
them first (Experiment 0). The crate's own frozen substrate is the
Experiment-0-verified corpus in `src/data/corpus.rs`, decoded by the engine
base-7 decoder in `src/data/generator.rs`.

- **eyes.json** (digit strings 0–4, delimiter = 5): `https://github.com/ngraham20/NoitaCryptographyResearch` (file `eye/eyes.json`) [confirmed]
- **data.csv** (alternate transcription): `https://github.com/Doctor-Ned/NoitaEyeGlyphResearch` [confirmed]
- **noitaGlyphs.txt / trigram bruteforce data**: `https://github.com/ToboterXP/EyeGlyphs` (`archive/eyeGlyphs-trigram order bruteforce.py`) [confirmed]
- **Xkeeper0 PHP transcoder** (the engine-decode reference, base-7 over 64-bit ints): `https://gist.githubusercontent.com/Xkeeper0/a6eda18571ef889be291822c400cc6c8/raw` [confirmed]
- **Primary doc** (encoding rules, spawn conditions): `https://docs.google.com/document/d/1s6gxrc1iLJ78iFfqC2d4qpB9_r_c5U5KwoHVYFFrjy0` [confirmed]
- **CodeWarrior0 analyses repo** (reference implementations): `https://github.com/codewarrior0/noita-eye-glyph-analyses` [confirmed]
- **Wiki (statistical claims, reading orders)**: `https://noita.wiki.gg/wiki/Eye_Messages` [confirmed]

---

## Experiment 0 — Cross-validate the four transcriptions (the prerequisite)

Priority: highest — everything downstream depends on it.

**Status:** Done and frozen. The verified corpus is `src/data/corpus.rs`: its
engine base-7 decode is cross-checked byte-for-byte against the ngraham20
transcription for all nine messages, so every downstream statistic rests on solid
ground. The engine decoder is `src/data/generator.rs`.

**Hypothesis tested:** The independent transcriptions (ngraham20 `eyes.json`,
Doctor-Ned `data.csv`, ToboterXP `noitaGlyphs.txt`, Xkeeper0 PHP output) agree
byte-for-byte on all 9 messages.

**Method:**
1. Normalize each source to one canonical representation: per-message decimal trigram sequence (after the agreed reading order) and the raw 0–4 digit string with delimiter removed.
2. Run Xkeeper0's PHP transcoder (`php eye.php`, needs bcmath) to regenerate ciphertext from the hard-coded `[u32,u32]` pair arrays — this is the closest thing to engine ground truth since it mirrors the decompiled base-7/64-bit decode [confirmed].
3. `diff` all four element-wise.

**Interpretation:** A clean match across all four validates the dataset. Any
divergence is critical — it means at least one widely-cited analysis was run on
corrupted ciphertext, which would silently invalidate isomorph/frequency claims.
The verified corpus captures that clean match as the crate's ground truth.

**Note on layering [confirmed]:** Xkeeper0's decode is base-7 over 64-bit
integers emitting −1..5 (5 = newline) — the *engine* storage layer. The base-5
trigram (0–124) is the *human reading* of rendered glyphs. These are two
different layers; do not conflate them.

---

## Experiment 1 — Reading-order multiple-comparisons audit (the decisive test)

Priority: highest — the experiment that most directly tests whether the headline
probability is honest. (Caveat: the raw *order count* alone is unlikely to
overturn it — the real exposure is researcher degrees of freedom; see the
interpretation.)

**Status:** Implemented. The fixed standard-36 null lives in
`src/nulls/null/mod.rs` (`cargo run -- nulltest`); the broader configured
researcher-degrees-of-freedom correction lives in `src/nulls/dof_null/mod.rs`
(`cargo run -- dofnull`).

**Hypothesis tested:** The "exactly one of 36 reading orders yields an unbroken
0–82 range" result is genuinely improbable under chance, and is *not* an artifact
of testing many orders and reporting the prettiest one.

**Method:**
1. Reconstruct the 9 glyph grids from raw data (rows split on delimiter; widths confirmed to be 39 with the bottom two rows differing by ≤1) [confirmed].
2. Implement all 36 "standard" reading orders and Toboter's broader ~86,000-order space (`https://github.com/ToboterXP/EyeGlyphs`) [confirmed].
3. For each order: decode trigrams base-5 → base-10 across all 9 messages combined; record (a) number of distinct values, (b) whether the value set is a contiguous range, (c) the range span.
4. Build a null distribution: generate thousands of random glyph grids of identical dimensions, run the *same* 36-order (and ~86k-order) search on each, and record how often *at least one* order produces a contiguous 83-value (or any contiguous) range. This is the multiple-comparisons correction the community's `(83/125)^1036` figure omits. Make the null's search space match the human one — resample not just the grid but also the digit→value mapping and the trigram grouping rule, since those were chosen after seeing the data too.

**Interpretation:**
- The naive per-order probability `(83/125)^1036` is real and reproduces (float64 `5.836e-185`; exact value `5.836200792956514e-185`) [confirmed], but it is the probability for *one fixed* order. The honest question is the family-wise probability across everything searched.
- **Trial count alone does not deflate it.** A Bonferroni/Šidák correction over even ~86k *fixed* orders leaves the outcome astronomically small *if* the null is independent-uniform trigrams — so the order count by itself does not overturn the claim. The real exposure is researcher degrees of freedom (the "garden of forking paths"): the reading-order *family*, the digit→value mapping, the grouping into trigrams, and the "contiguous range" statistic were all selected *after* looking at the data. The two corrections — fixed-order family-wise error vs. adaptive model selection — are separated and quantified below. When a selected headline has a known analytic null far below Monte-Carlo resolution, that analytic bound is corrected across the configured search space; a finite empirical p-value floor is not mistaken for deflation.
- **What the DoF null measures.** The DoF null does not compare raw statistic values across incommensurable cells: each traversal/grouping/statistic cell is first mapped to its own same-shape random-grid marginal tail from calibration set A. The eyes and an independent resampling set B then take the minimum calibrated p-value over the same search space while both are scored against A. With seed 12345, 1000 calibration trials, and 1000 resampling trials, the eyes' min marginal p sits at the empirical floor (`1/1001`), but 199/1000 resampling grids also reach an equally small calibrated min-p somewhere in the configured search. The add-one adaptive p-value is 200/1001 = 0.199800 (95% Wilson `0.176198..0.225697`; median Šidák-equivalent comparisons ≈173). The accepted honeycomb trigram contiguous-0..=82 cell is also at `1/1001`.
- **This is a finite-resolution diagnostic, not a deflation.** With only 1000 calibration grids, the empirical marginal p cannot represent the analytic per-order headline bound `(83/125)^1036 = 5.836e-185`. The 0.199800 value measures how often a random grid reaches the `1/1001` floor somewhere in the configured search; resolving the effect empirically would need about `1.7e184` calibration draws, so the honest headline correction is analytic. Over all 1140 configured traversal×grouping×statistic cells, Bonferroni/Šidák ≈ `6.653e-182`; over the empirical effective comparisons, ≈ `1.010e-182`. The fixed standard-36 null still supports the anomaly when the honeycomb family is treated as data-independent, and the bounded 0..=82 headline survives the broader configured DoF correction analytically.
- Independent computation shows the raw order gives 0–122 with gaps, so the contiguity is definitely order-contingent [confirmed]; this experiment quantifies whether that contingency is suspicious or benign, and the answer above is that the analytic headline survives while the naive `(83/125)^1036` framing omits the family-wise correction [disputed against community framing].

---

## Experiment 2 — Generation-pipeline artifact test (encoding, or a side effect of the base-7 pipeline?)

Priority: high — directly attacks the "meaningful plaintext" assumption.

**Status:** Implemented. `src/nulls/pipeline_null/mod.rs` (`cargo run -- pipelinenull`)
runs both halves, each routed through the real `src/data/generator.rs` decode:
`run_pipeline_null` (the structure-matched null) and `input_randomness_report`
(the negative control).

**Hypothesis tested:** The 0–82 contiguity and isomorph structure are partly an
artifact of the deterministic generation pipeline (fixed 64-bit number → repeated
division by 7 → −1 mapping), not evidence of an enciphered natural-language
plaintext [speculative; a live concern, not established].

**Method:**
1. Implement the documented generator and confirm it reproduces the wiki's worked example: `int('acf686745634505c',16) = 12463296853015023708` → base-7 expansion → drop trailing 0 → subtract 1 → `[2,0,1,0,1,3,2,2,3,3,0,4,0,4,1,1,3,0,2,3,2,1]` [confirmed — reproduced in dossier].
2. Feed random inputs through the *same* pipeline — but constrain them to the real structure: match the per-message `[u32,u32]` block count, the output lengths, the delimiter layout, and the valid symbol alphabet. Unconstrained random 64-bit integers do not preserve block lengths, delimiter placement, or the "no internal −1" behaviour, so they are only a separate *negative* control, not the null. Also push known natural-language plaintexts through it.
3. Run the identical trigram/range and isomorph analyses on these synthetic outputs.

**Interpretation / result:**
- The structure-matched null confirms empirically that the base-7 pipeline manufactures *no* reading-layer contiguity: the `0..=82` range essentially never appears, just as it does not for uniform-orientation cells. So the contiguity is not a pipeline artifact.
- The negative control shows genuine random integers from the same matched-length, `u64`-capped model decode to hundreds of `-1` control symbols and hundreds of delimiters per corpus, whereas the real messages contain zero `-1` and only 86 delimiters. The inputs are therefore deliberately authored in the `0..=5` alphabet (engine-generated structured data), not random — which says nothing about whether the authored content is a *recoverable* message.
- **Honest reading:** "not a pipeline artifact" only means the specific authored digit values matter; uniform-random cells also never produce the contiguity, so the result is equally consistent with structured-but-meaningless data. Flat pipeline output rules the crude artifact hypothesis *out*; it does not rule a real message *in* [would still be a major correction if it had reversed].
- **Radix note:** division by 7 yields remainders 0–6, minus 1 → −1..5. The documented transcoder emits `(a % 7) − 1` directly, where −1 and 5 behave as control/newline values rather than glyph orientations — so "are the values clamped or mod-5'd?" is a strawman unless the engine code actually clamps [disputed — wiki prose says "converted into 0-5", but the mechanism is base-7].

---

## Experiment 3 — Structural divisibility & trigram-count reproduction

Priority: medium (sanity baseline).

**Status:** Confirmed and reproduced multiple times in the dossier; it is a
baseline invariant of the verified corpus rather than an open experiment.

**Hypothesis tested:** Every message's eye count is divisible by 3; total
trigrams = 1036; the `(83/125)^1036` figure is internally consistent.

**Method:** Strip delimiter (5), assert `len % 3 == 0` per message; sum `len/3`;
recompute `(83/125)**1036`.

**Result:** Counts `{297,309,354,306,411,372,357,360,342}` all divisible by 3;
sum = 1036; probability = `5.8362007929568295e-185` [confirmed].

**Caveat to flag:** Divisibility holds only when counting eyes, excluding
delimiters — the raw string lengths (including delimiters) are mostly *not*
divisible by 3 [confirmed]. A high-precision recomputation gives `...6514e-185`
in the trailing digits; the wiki's published mantissa `...68295` is a float64
rounding artifact [confirmed — minor numerical defect in the wiki figure].

---

## Experiment 4 — Frequency / entropy / IoC: is it really non-monoalphabetic?

Priority: high — the core "is there signal" test.

**Status:** Implemented. `cargo run -- stats` reports frequency, entropy, and IoC
for the rendered digits; `cargo run -- orders` audits the reading orders and the
Experiment-4 flatness across them.

**Hypothesis tested:** The trigram-value (0–82) frequency distribution is
statistically flat, ruling out simple monoalphabetic substitution of a
natural-language plaintext.

**Method:**
1. On the accepted reading order, build the unigram histogram over the 83-symbol alphabet.
2. Compute chi-square goodness-of-fit vs uniform; compute index of coincidence (IoC).
3. Repeat on the raw stored order and on several alternative orders to see how order-dependent flatness is.
4. Cross-check against `codewarrior0/simple_freq.py` and `SirCapybar/NoitaEyeGlyphResearch` IoC routines as reference implementations [confirmed these exist].

**Interpretation:**
- Community reports median frequency ~12, mean ~12.48, IoC ~1.066 (near-random) [confirmed via CodeWarrior0 doc].
- Flat distribution + IoC near `1/83` → consistent with polyalphabetic, inconsistent with monoalphabetic substitution of skewed natural-language text. This is sound cryptographic reasoning [confirmed], but it is community analysis, not dev-confirmed.
- **Interpret skeptically:** flatness is *also* exactly what structured-but-meaningless data (e.g., the base-7 pipeline output) yields. Flat frequency rules monoalphabetic *out*; it does not rule a real message *in*.

---

## Experiment 5 — Periodicity & autocorrelation (Vigenère family ruled out?)

Priority: medium.

**Status:** Implemented. The period/lag/Kasiski battery lives in
`src/experiments/periodicity/mod.rs` (`cargo run -- periodicity`).

**Hypothesis tested:** The ciphertext is aperiodic (no fixed key period),
supporting the polyalphabetic/autokey conclusion and ruling out plain
Vigenère/Caesar.

**Method:** Run Kasiski / autocorrelation / IoC-by-period (`codewarrior0/stat_period.py`)
over candidate periods. Separately brute-force all 83 Caesar shifts and short
Vigenère keys over the 0–82 stream and score outputs against English and Finnish
n-gram models (Toboter ships both corpora; the plaintext language is unknown)
[likely Finnish or English].

**Interpretation:** No dominant period; no Caesar/Vigenère key yields
language-like statistics. A positive (readable plaintext) would be a sensational
result and should be triple-checked against Experiment 0 data integrity before
any announcement.

---

## Experiment 6 — Adjacency & distance-4 anomaly on raw vs reordered data

Priority: high — exposes the circularity directly.

**Status:** The zero-adjacency null is implemented as
`src/nulls/zero_adjacency_null/mod.rs` (`cargo run -- zeroadjnull`, Experiment
7D): it scores the zero-adjacency property against a within-message multiset
shuffle. The raw-order adjacency/distance measurements below are confirmed.

**Hypothesis tested:** "No symbol twice in a row" and "distance-4 recurrence at
~2× expected rate" are properties of the correctly reordered ciphertext, not of
the raw data.

**Method:**
1. On raw stored order: count adjacent-equal trigrams and build the recurrence-distance histogram.
2. On the accepted reading order: repeat.
3. Cross-check against `codewarrior0/repeats.py` [confirmed exists].

**Interpretation:**
- Independent computation found, on the raw order: 17 adjacent-equal trigrams (not zero), and distances 1/3 (17/15) *higher* than distance 4 (10) — i.e., the celebrated anomalies do not appear [confirmed, disputed against community framing].
- Therefore: if a candidate reading order drives adjacent-equal to 0 and produces a genuine distance-4 spike at ~2× baseline, that order is corroborated as intended. This makes "adjacent-equal == 0" a candidate discriminator among reading orders — but it is not statistically independent of contiguity when searched over the same 36/86k orders, so it carries its own multiple-comparisons burden. Use it to *confirm* Experiment 1's single winning order (one order, one test), or, if you *search* on it, fold it into the same family-wise null as contiguity and distance-4 and score the three jointly — never report it as a free independent check.
- If *no* order simultaneously satisfies contiguity and zero-adjacency and the distance-4 spike, that tension itself is evidence the model is overfit.

---

## Experiment 7 — Isomorph detection & the "Alphabet Chaining" failure

Priority: medium-high.

**Status:** Implemented; the formerly missing nulls and controls are closed. The
within-message isomorph shuffle null is `src/nulls/isomorph_null/mod.rs`
(`cargo run -- isomorphnull`, 7A); the known-succeed/known-fail chaining controls
are `src/analysis/chaining/mod.rs` (`cargo run -- chaining`, 7B); the same-offset
shared-region recurrence null is `src/nulls/perseus/mod.rs`
(`cargo run -- perseus`, 7C). These constrain the cipher-family discussion but do
not decode the eyes.

**Hypothesis tested:** Genuine isomorphs (repeated relative-pattern segments)
exist across messages, consistent with a plaintext-driven polyalphabetic
permutation cipher; and the classical "alphabet chaining" attack fails for a
structural reason (non-commutativity), not because the isomorphs are spurious.

**Method:**
1. Run isomorph detection across the 9 sequences to locate repeated relative-pattern segments (`codewarrior0/isomorphs.py` as reference) [confirmed exists].
2. Build a randomized-shuffle null: how often do isomorphs of the observed length appear in shuffled data of the same alphabet/length? (Implemented in `isomorph_null`.)
3. Attempt alphabet chaining on the discovered isomorphs and confirm it does not yield consistent plaintext [confirmed it fails per wiki], against the matched known-succeed/known-fail controls (`chaining`).
4. Test Perseus's permutation observation: symbols in non-shared sections allegedly never reappear in later size-≥2 shared sections (claimed p ≈ 0.192% by chance) — reconstruct aligned shared/non-shared regions and compare the empirical rate to a shuffle null (`perseus`) [confirmed claim exists].

**Interpretation:**
- Isomorphs significant above null + chaining fails is *consistent with* a non-commutative permutation cipher (Chaocipher/Hutton/S_83 family) but does not establish one [speculative]: chaining can also fail from a wrong reading order, misalignment, short/noisy isomorphs, a transcription error, an implementation bug, or a wrong-plaintext assumption. The synthetic known-succeed / known-fail controls exist precisely so the eye corpus can be matched against the known-fail signature, not merely observed to "fail".
- Isomorphs at chance level would mean the "structure" is weaker than claimed and the cipher inferences are overbuilt; the null does not show that.
- **Perseus recurrence null result:** the implemented operational definition treats same-offset common runs of length ≥2 as shared when they are in the earliest leading-family alignment or an East/West counterpart pair; all other positions are non-shared. Scanning each message left-to-right, a shared-position symbol is recurrent if it appeared earlier in a non-shared position in that same message. Under that definition, seed 12345 / 1000 within-message shuffles gives observed 0/185 recurrences and add-one lower-tail p 7/1001 = 0.006993. This corroborates Perseus's structural constraint beyond the shuffle null but decodes nothing and remains conditional on the accepted honeycomb reading order and this documented-region interpretation.
- **Global transposition note:** the accepted-honeycomb message lengths are all distinct (`99,103,118,102,137,124,119,120,114`), while the documented shared runs stay at the same ciphertext offsets across messages (all-nine `[66,5]` at offset 1; East/West counterpart runs of 24, 20, 2, and 5). A columnar/route/rail-fence transposition is a length-dependent permutation, so a single global transposition route would not naturally preserve those same-offset anchors across unequal lengths. This disfavors global transposition, including substitution-then-global-transposition under one shared route, as the eyes' mechanism. It is evidence against the natural global model, not an impossibility proof, and does not rule out per-message or non-global schemes.
- Note the echo-chamber risk: nearly all isomorph work traces to Lymm + codewarrior0. The independent null/control gap for Experiment 7 is now closed in this repo; the remaining blocker is not another pure-crate statistic but the unknown external meaning/key/mapping needed for any decode claim.

---

## Experiment 8 — Brute-force base-N reinterpretation cross-checked against known alphabets

Priority: medium.

**Status:** Implemented. `cargo run -- grouping` enumerates the base-N groupings
and reports the independent state-count estimate.

**Hypothesis tested:** The base-5 trigram model is the correct alphabet layer (vs
base-7, vs single-glyph base-5, vs other groupings), tested by which
interpretation best matches a plausible plaintext alphabet size.

**Method:**
1. Enumerate candidate interpretations: single glyphs (base-5), trigrams (base-5 → 0–124), the engine base-7 stream, pairs, tetragrams.
2. For each, compute alphabet size actually used, entropy, and fit to candidate plaintext alphabets (26-letter English, ~29-letter Finnish, ASCII).
3. The "83 distinct values" closely matching plausible 2× alphabet or rune-wheel sizes is suggestive but the 83 Elder Futhark runes are an arbitrary researcher display mapping, not in-game runes [confirmed] — do not over-read it.

**Interpretation:** A base/grouping whose used-alphabet size and entropy cleanly
match a real language alphabet is a candidate. **Skeptical note:** "83 states ≈
83 distinct glyph values" risks being circular — the state-count estimate may
simply equal the alphabet size [disputed]. Estimate internal states
*independently* (via isomorph-length distributions / unicity distance) and check
whether you recover ~83 without assuming it. This is now superseded rather than
merely disputed: under the surviving cipher-family theories (GAK on a near-S₈₃
state group), the true state space is S₈₃-scale (83! ≈ 10¹²⁴), not ~83 —
the old "~83 states" figure reflects the earlier, pre-GAK custom-Alberti-era
framing.

---

## Experiment 9 — Seed-invariance of content

Priority: medium — tests a load-bearing but unproven assumption.

**Status:** The analysis half — a byte-for-byte cross-seed diff test — needs no
game access and is trivial to run the moment a second-seed transcription is
vendored under `research/data/`. That vendored second-seed transcription is the
open item; until it lands, seed-invariance rests on qualitative observation, not
a byte-for-byte proof.

**Hypothesis tested:** Eye-message *content* (the trigram value sequence) is
identical across world seeds; only *locations* are seed-dependent.

**Method:**
1. Use Lymm's Binoculars (`https://gitlab.com/realgonzogames/lymms-binoculars`) or noita-telescope (`https://github.com/Lymm37/noita-telescope`) to get coordinates for ≥2 seeds [confirmed tools].
2. Capture glyphs in-game (unmodded — eyes do not spawn if mods were ever active this run, and only on `background_cave_02.png` after the "Entered East/West" trigger) [confirmed conditions], or reproduce via the engine.
3. Transcribe to trigrams and diff content across seeds.
4. Verify the X-mirroring relationship: for seed 1249563923, East1 (22064,−6079) / West1 (−49616,−6079) [confirmed in wiki table; not re-verified in-game].

**Interpretation and current state:** Identical content across seeds = content is
hardcoded/seed-invariant (the community assumption). The repo owner reports, from
direct in-game observation across multiple world seeds, that the eye-message
content is identical — a qualitative (eyeballed) corroboration of seed-invariance
that no prior source had provided. This is *not* the byte-for-byte trigram diff
across ≥2 named seeds that remains the gold standard, which is still open pending
a vendored second-seed transcription. Any per-seed content variation would be a
major finding overturning the premise that there is a single fixed message to
solve; the qualitative evidence points against that, but the strong form is
unproven.

---

## Experiment 10 — Sprite-state extraction & clustering (verify the 0–4 orientation mapping)

Priority: low — the mapping is maintainer-attested as binary-verifiable (see
below); this experiment is now an optional independent re-extraction, not a
resolution of a genuinely unverified link.

**Status:** The digit→direction *labeling* is binary-verifiable from the
shipped engine per **[Lymm]** (maintainer-confirmed 2026-07-06), not yet
independently re-extracted in this repo; the *count* is corroborated.
Sprite-clustering from in-game pixels (or the decompiled render path) remains
the only way to re-derive the mapping from primary pixels in this repo, but the
result is cryptanalytically immaterial either way.

**Hypothesis tested:** The specific digit→direction mapping (0=center, 1=up,
2=right, 3=down, 4=left) is correct, and there are exactly 5 visually distinct
orientations.

**Method:**
1. The glyphs are engine-rendered with no sprite assets in `data.wak` [confirmed] — so you cannot extract sprites from the archive. Instead, capture rendered eye images in-game (per Experiment 9 conditions) or from the decompiled render path in Ninji's Ghidra project.
2. Cluster the captured eye images (k-means / template matching) to confirm exactly 5 visual states.
3. Cross-map clusters to the digit values produced by the generator for the same positions.

**Interpretation and current state:**
- 5 clean clusters confirm the 5-orientation model. The repo owner, from direct in-game observation, confirms exactly 5 visually distinct orientations, corroborating the already-`[confirmed]` 0–4 inventory.
- The exact direction-per-digit mapping is shown only as an image on the wiki/primary doc, and one source (Cipherbrain) warns the numbering order is non-obvious. **[Lymm]** The eye sprites are hardcoded in the engine's drawing function and can be extracted directly from the shipped binary, so the mapping is binary-verifiable, not merely image-sourced — maintainer-confirmed 2026-07-06, not yet independently re-extracted in this repo (an optional Ghidra follow-up in the `…-ghidra` worktree could close that gap). So the *mapping* sub-claim resolves as "maintainer-attested, verifiable on demand, independent re-extraction pending" rather than "unverifiable" [likely — maintainer-attested; independent re-extraction pending].
- **This is cryptanalytically immaterial:** all downstream statistics run on the engine-fixed integer digit sequence (cross-validated byte-for-byte in Experiment 0), so a relabeling of the direction names permutes no value and changes no result. The only thing that would still matter is a *mis-assignment of which integer belongs to which glyph during transcription* — and that is exactly what Experiment 0 already rules out.

---

## Experiment 11 — Reproduce the methodology that solved other Noita ciphers (calibration)

Priority: medium — provides a positive control.

**Status:** Implemented. The positive-control battery lives in
`src/experiments/controls/mod.rs` (`cargo run -- controls`).

**Hypothesis tested:** The analytical pipeline used here actually works on Noita
ciphers that *are* solved — i.e., the tooling isn't systematically blind.

**Method:** Apply the same frequency/IoC/substitution tooling to the solved Noita
symbol systems as positive controls:
- Common Glyphs (map 1:1 to English: "SEEK THE END", "BRING THE TREASURE HERE") [confirmed solved].
- Orb-Room glyphs (Finnish creation-myth text) [confirmed solved].
- The Cessation Cipher Quest (decodes to "SEEKING TRUTH, THE WISE FIND INSTEAD ITS PROFOUND ABSENCE") — a fully-solved multi-step Nolla cipher [confirmed], at `https://noita.wiki.gg/wiki/The_Cessation_Cipher_Quest`.

**Interpretation:** Match the control to the tool. The Common Glyphs (a 1:1
monoalphabetic map → "SEEK THE END") are the right positive control for the
frequency/substitution pipeline and *should* be recovered cleanly; the Orb-room
Finnish text is a language-scoring control. The Cessation Cipher is a multi-step
image/key puzzle — the frequency/IoC/substitution tooling will not "recover" it
without puzzle-specific machinery, so cite it only as proof that Nolla designs
solvable ciphers, not as a tooling control. For the isomorph/chaining tooling,
build *generated* polyalphabetic/autokey fixtures with known keys as the matched
controls. If the matched controls pass, a *null* on the Eye Messages is
meaningful (the tools work; the eyes are genuinely harder or not a simple
cipher); if they fail, the methodology is suspect. **Important caveat:** the
Cessation Cipher is a separate puzzle and must not be conflated with the eyes as
evidence the eyes are solvable [confirmed — common conflation error].

---

## Experiment 12 — Candidate-cipher implementations (incrementing wheel / Chaocipher / S_83 deck)

Priority: lower — this is the open research frontier, not a verification.

**Status:** The language-scoring null harness is implemented as
`src/attack/cipher_attack/mod.rs` (`cargo run -- cipherattack`); the specific
candidate-cipher models remain the open frontier and no model yet yields readable
plaintext.

**Hypothesis tested:** A specific live model (ngraham20's "incrementing wheel":
83-glyph outer ring + gapped-plaintext inner ring rotating one step per char; or
an S_83 group-autokey / deck cipher) can reproduce the eyes' isomorph statistics
and yield language-like plaintext.

**Method:**
1. Implement the wheel from `ngraham20/NoitaCryptographyResearch` (Rust/Python `src/`) and its inverse; run over the correctly-ordered ciphertext for various inner-ring alphabets/gap patterns; score outputs with English/Finnish n-gram models [confirmed model exists, unproven].
2. Implement single-83-wheel vs S_83 deck-shuffle (Lymm's GAK-over-S_83 model); encipher Finnish/English test text; compare IoC, no-double property, and isomorph stats against the real eyes. Toboter's `best.out` uses a Tolkien text as a known-plaintext GA test target [confirmed].

**Interpretation:** A model that simultaneously reproduces the eyes' flat
frequency, zero-adjacency, distance-4 spike, *and* isomorph structure — and
yields readable plaintext — would be a solution. The community has tried
Chaocipher/Hutton/alphabet-chaining and they failed [confirmed]; the live concern
is possible plaintext/ciphertext corruption defeating perfect isomorphs
[confirmed the community hypothesizes this]. Treat any "solution" without a fully
disclosed, reproducible method as not credible — the wiki's own rule [confirmed].

---

## Current state and what genuinely remains open

The null/control battery these experiments called for is now built and runnable:

1. **Experiment 0** (transcription cross-validation) — the non-negotiable prerequisite; done and frozen as the verified corpus (`src/data/corpus.rs`).
2. **Experiment 1** (reading-order multiple-comparisons audit) — the fixed standard-36 null and the researcher-DoF correction are built; the naive `(83/125)^1036` framing omits the family-wise correction, but the bounded 0..=82 headline survives the configured DoF correction *analytically* [disputed against community framing].
3. **Experiment 2** (generation-pipeline artifact test) — built; the contiguity is not a base-7 pipeline artifact, but flat output is equally consistent with structured-but-meaningless data.
4. **Experiments 4 & 6** (frequency/IoC + adjacency on raw vs reordered) — built; they expose how much "signal" is order-induced [confirmed it is substantial].
5. **Experiment 11** (positive controls on solved ciphers) — built, so a null on the eyes is meaningful (the tooling recovers the solved controls).

The genuine remaining open items are external, not pure-crate statistics: a
vendored byte-for-byte cross-seed transcription diff (Experiment 9), and an
external anchor for the eyes — key material (the letter→action assignment), a
method/cipher-family disclosure, or known plaintext (Experiment 12's frontier).
There is no fixed symbol-to-meaning table to anchor: the cipher is
polyalphabetic, so the plaintext-letter→group-action assignment IS the key to
be recovered, not a lookup table that could be externally supplied.

**Two standing caveats grounding all of the above:**
- **On developer confirmation:** a relayed-verbatim developer quote (Arvi, 2021-10-15 Twitch stream, relayed by FuryForged) confirms the eyes carry an *intentional* message and are "very difficult" — so intentionality ("there is a message") is dev-attested. But that quote discloses no cipher, key, method, or solution, and no primary developer statement confirms the Eye Messages encode *recoverable plaintext*. The separate "developers confirmed it's meaningful/solvable" claim that traces to an unsourced 2022 Hacker News intro line and AI-generated/Grokipedia text is a debunked meta-claim [confirmed] and must not be upgraded into a solvability confirmation. The strongest honest statement is unchanged: the eye data is deterministic, engine-generated, strikingly structured data of unknown meaning; unsolved; no primary developer source confirms it encodes recoverable plaintext.
- **On reproduction breadth:** the entire technical corpus rests on a handful of analysts (Lymm, CodeWarrior0, Toboter, Pyry, Perseus) and a few repos/Google Docs; independent reproduction beyond this group is thin [confirmed]. The crate has now added the key independent null distributions for Experiments 1, 2, and 7, including the researcher-DoF correction and the Perseus recurrence null. The genuine remaining open items are external: a vendored byte-for-byte cross-seed transcription diff, and an external anchor for the eyes — key material (the letter→action assignment), a method/cipher-family disclosure, or known plaintext.
