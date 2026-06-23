# HANDOFF — autonomous continuation of the Noita eye-puzzle workbench

You are picking up an in-progress cryptanalysis workbench. **You will run for a
long time with no human available to answer questions or give direction.** That
is expected. Your job: **make as much correct, verified progress as you can**,
delegating the implementation heavily to **codex**, committing as you go, and
never overstating what the data shows.

If something is ambiguous, **make a reasonable decision and proceed** — do not
stop to ask. Document the decision in your commit message and in the progress log
(see end of file). Favor thoroughness over speed; token cost is not a constraint.

---

## 1. Autonomy contract (read first)

- **Do not wait for input.** There is no human in the loop. When you would
  normally ask a question, pick the most defensible option, write down why, and
  continue.
- **Make progress in a loop:** pick the top unblocked item from the Work Queue
  (§6) → delegate to codex → verify yourself → review if non-trivial → commit →
  append to the progress log → repeat. Keep going until the queue is exhausted or
  you hit a hard external blocker (e.g. network down for a data fetch).
- **Never break the gate.** `make check` must be green before every commit. A red
  gate means "not done", not "commit anyway".
- **Never overstate findings.** The strongest defensible claim about the eyes is:
  *"deterministic, engine-generated, strikingly structured data of unknown
  meaning; unsolved; no primary developer source confirms it encodes recoverable
  plaintext."* Print nothing stronger. Never present an uncomputed or
  placeholder-derived number as a finding.

---

## 2. What this project is

A `std`-only Rust workbench for **trustworthy** cryptanalysis of Noita's "Eye
Messages": primitives that *constrain the hypothesis space* and *add the null
distributions the community never computed*, rather than making premature claims.
Full skeptical research dossier is in `research/` (read `research/README.md`,
then `research/05-code-investigations.md` = the 13-experiment plan, and
`research/07-workbench-bridge.md` = experiment→module build order).

Project rules live in `AGENTS.md` (codex reads this itself — you don't need to
restate it in prompts). Highlights: `unsafe` forbidden; no panic/unwrap/indexing
in lib/CLI code (relaxed in tests); document every public item; `--locked`
everywhere; std-only (crates.io was offline at init — add an in-crate PRNG, not a
crate). Toolchain is pinned (Rust 1.96.0).

---

## 3. What is already DONE (do not redo)

Commits `ac0bcd7`→`2bdb0c0` on `master`, all gate-green. Verified independently.

- **Experiment 0 (transcription cross-validation):** the 9 real messages are
  ingested in `src/corpus.rs` with provenance. A test independently re-derives the
  engine base-7 decode from Xkeeper0's `[u32,u32]` pairs and asserts it equals the
  ngraham20 transcription **byte-for-byte for all 9** (it does). Vendored raw
  inputs: `research/data/eye-messages/ng_eyes.json` and `.../xk_eye.php`.
- **Experiment 3 (counts):** eye counts `{297,309,354,306,411,372,357,360,342}`
  all ÷3; total **1036** trigrams; `(83/125)^1036 = 5.836e-185`; raw lengths
  *with* delimiters mostly NOT ÷3. All as tests.
- **Experiment 1A + Experiment 6 (reading orders):** `src/orders.rs` reconstructs
  the 9 glyph grids (split rows on delimiter `5`; verified row widths, max 39,
  bottom two rows differ by ≤1), implements a **data-independent honeycomb
  interlocking-triangle walk** plus the `standard36` family (6×6 trigram-digit
  permutations), and computes per-order stats. CLI: `cargo run -- orders`.
  - Raw stored order: 114 distinct, span 0–122 (9 gaps), 31 values >82, **17**
    adjacent-equal, recurrence d1..6 = `17,12,15,10,10,9` (no distance-4 spike).
  - Honeycomb winner `standard36-u012-d012`: **83 distinct, contiguous 0–82, 0
    above 82, 0 adjacent-equal**, recurrence `0,5,9,26,11,11` (clear d4 spike).
    All three "cipher properties" appear ONLY under this order — confirming the
    order-contingency thesis.
- **Experiment 1B (the decisive null):** `src/null.rs` — std-only deterministic
  `SplitMix64`, Wilson intervals, Monte-Carlo over random grids of identical
  per-message shape searched across the same 36-order family, plus analytic
  Bonferroni/Šidák. CLI: `cargo run -- nulltest --seed <u64> --trials <n>`.
  - Headline contiguous-0–82: **0/1000**. Min distinct ever reached: 122 (never
    near 83). Ceiling always 124 (never bounds at 82). Zero-adjacency: ~1–2/1000.
    Real distance-4 ratio 2.52 exceeds all 2000 random best-over-36 ratios.
  - Bonferroni/Šidák over 36 orders = `2.10e-183`. **Conclusion (already
    documented in the CLI):** the family-wise correction does NOT deflate the
    per-order improbability; the dominant remaining deflationary risk is the
    *unmodeled researcher-degrees-of-freedom* (the traversal family, grouping
    rule, and headline statistic were chosen after seeing the data — the null
    deliberately does not resample those). Keep this honesty in everything.
- **Review:** a `codex review` over the whole diff found only one P3 (silent
  trigram truncation), now fixed (`2bdb0c0`): `Message::trigrams()` errors on
  non-÷3 input.

### Continuation experiments (2, 11, 4, 5, 7, 8, 12) — all gate-green, reviewed, verified

Each pairs a measurement with a null or positive control; all eye results are
negative, all calibration controls fire. Full one-liners with SHAs are in §9.

- **Exp 2 — generation-pipeline artifact null** (`generator.rs`, `pipeline_null.rs`):
  the base-7 pipeline does **not** manufacture the bounded 0–82 contiguity (uniform
  cells don't either) ⇒ not a generation artifact; negative control only shows the
  authored inputs live in the 0–5 storage alphabet. Review fixes: unbiased
  rejection sampler + exact cap-aware no-`-1` rate.
- **Exp 11 — positive controls** (`controls.rs`): a monoalphabetic 1:1 substitution
  control preserves IoC/frequency multisets and separates from uniform; an
  isomorph/period control recovers a repeating-key Vigenère period while
  autokey/running-key stay quiet. The first isomorph control was caught
  **degenerate** and redesigned — see §5.
- **Exp 4 — frequency/entropy/IoC across orders** (`analysis.rs` chi-square +
  `orders.rs`): honeycomb winner is the only standard36 order fully inside 0–82;
  mean freq 12.48, concatenated normalized IoC **1.066** (matches community), χ² vs
  uniform 150.355. Flat freq rules monoalphabetic OUT, not a message IN.
- **Exp 5A — periodicity/autocorrelation** (`periodicity.rs`): no period/lag clears
  the random-null band; verdict derived from the flags; explicit distance-4
  reconciliation with Exp 1B (family-wise vs pointwise).
- **Exp 5B-1 — English/Finnish language scorer** (`language.rs`, corpora under
  `research/data/lang/`): held-out bigram log-likelihood discriminates the two
  languages (calibration positive control); reusable by Exp 12. Exp 5B-2's
  Caesar/Vigenère-vs-language brute was folded into Exp 12.
- **Exp 7A — isomorph shuffle null** (`isomorph.rs`, `isomorph_null.rs`): the eyes
  do **not** exceed their within-message shuffle null for repeated-signature counts
  — the missing community null, computed and negative.
- **Exp 7B — alphabet chaining** (`chaining.rs`): the eyes match the known-fail
  chaining signature, not the known-succeed Vigenère band (additive model).
- **Exp 8 — base-N grouping + independent state count** (`grouping.rs`): no grouping
  is both alphabet- and entropy-compatible with a language; a collision estimator
  calibrated on known-N (not assuming 83) gives ≈ 73–90 ⇒ ~83 genuine near-uniform
  states.
- **Exp 12 — candidate ciphers** (`ciphers.rs`, `cipher_attack.rs`):
  Caesar/Vigenère/incrementing-wheel/Chaocipher/S₈₃-deck scored vs English/Finnish
  under guessed mappings yield no decryption above chance (best excesses ~21–293×
  below a recovered plant); a plant positive control is recovered, proving the
  harness is not blind. Interpretation made statistically rigorous (exceedance-rate
  diagnosis + effect-size contrast).

A cross-experiment **completeness pass** (read-only audit) confirmed: gate green,
shared anchors agree across all modules, every statistic has a null/control, and no
source text overstates. The synthesized conclusion lives in `README.md` (Results).

Modules (17): `glyph.rs`, `trigram.rs`, `generator.rs`, `corpus.rs`, `analysis.rs`,
`orders.rs`, `null.rs`, `pipeline_null.rs`, `isomorph.rs`, `isomorph_null.rs`,
`periodicity.rs`, `chaining.rs`, `grouping.rs`, `controls.rs`, `language.rs`,
`ciphers.rs`, `cipher_attack.rs`. CLI (`main.rs`): `demo`, `stats`, `orders`,
`nulltest`, `pipelinenull`, `periodicity`, `isomorphnull`, `chaining`, `grouping`,
`cipherattack`, `controls {monoalphabetic|isomorph(=polyalphabetic)}`.

---

## 4. How to work here (operating manual)

### Delegate implementation to codex, with autonomy
Give codex goals + constraints + verified inputs, and let it choose the design —
do NOT prescribe step-by-step. Keep each run focused (≤~3 coupled changes; split
otherwise). codex reads `AGENTS.md`/`CLAUDE.md` itself.

**exec (implementation):**
```sh
cat > /tmp/codex-<task>-prompt.txt <<'EOF'
<goals, constraints, verified inputs labeled "verify, don't trust", definition of done, "commit in logical steps">
EOF
\codex -c sandbox_mode=danger-full-access -a never exec \
  < /tmp/codex-<task>-prompt.txt > /tmp/codex-<task>.log 2>&1
```
Run it **in the background** (your harness's background mechanism), stdin closed,
output to a log. Runs take 10–30+ min; rely on the completion notification, don't
poll. A quiet log is not a hang.

**review (after any non-trivial diff):**
```sh
\codex -c sandbox_mode=danger-full-access -a never review --base <baseSHA> \
  < /dev/null > /tmp/codex-review.log 2>&1
```
Relay findings with their `[P0]/[P1]/[P2]` tags; **apply P0/P1** (delegate the fix
to a focused codex exec). P2/P3 at your judgment — but this repo's "no silent
failures / transcription-is-the-risk" ethos means data-integrity P3s are usually
worth fixing.

### One codex at a time; clean worktree
codex holds the workspace write-lock. **Never run two codex instances against this
repo at once.** Start each run from a clean worktree (commit/stash first). While
codex runs, do read-only inspection only.

### Verify yourself — trust neither side blindly
After each codex run: run `make check` (or at least `cargo test --locked`)
**yourself**. Two cautions learned here:
- codex's "make check passed" summaries were reliable, but **the harness's
  mid-edit `<new-diagnostics>` were repeatedly STALE** (phantom compile errors,
  even a wrong filename). The authoritative signal is running the gate yourself.
- For load-bearing correctness (independence tests, null event definitions),
  **spot-read the actual code** — confirm a cross-validation test isn't tautological
  and a null event isn't trivially-true (see §5 pitfalls).

### Sanity-check against the verified anchors (§3) after relevant changes
If a refactor changes the raw-order numbers, the honeycomb winner, or the null
results from the values in §3, something broke — investigate before committing.

### Commit discipline
Small logical commits, clear messages, gate-green each time. Don't rewrite
pre-existing history. The pre-commit hook (`make setup` installs it) runs the gate.

---

## 5. Pitfalls already discovered (don't relearn these)

- **"Contiguous" is trivially true for random full-range data.** A uniform-random
  grid fills ~all 125 trigram values → distinct≈125, span 0–124, which is
  "contiguous". The meaningful event is contiguous **bounded at 82** (distinct=83,
  ceiling=82). Always define null events to capture the *bound*, not bare
  contiguity.
- **Two layers, kept distinct:** storage/engine (base-7 over 64-bit ints, symbols
  −1..5, 5=newline) vs reading (base-5 trigrams of 0–4 → 0..124). Never conflate.
  The real corpus never decodes a `−1`.
- **Recurrence/adjacency must be per-message**, not across the concatenated stream,
  or you get artificial repeats at message joins. (`orders.rs` already does this.)
- **The digit→direction legend (1=up,2=right,…) is unverifiable from any text
  source.** Digit *identities* are datamined and fine; do NOT bake pixel-direction
  semantics into types or claims.
- **The honeycomb traversal is data-independent** (depends only on grid shape) and
  is validated by reproducing the known 0–82 result — that's why it's fair to hold
  it fixed in the null. If you add a *broader* order search, fold it into the SAME
  null (don't report it as a free independent check).
- **Positive controls/nulls can be methodologically degenerate or tautological
  even when gate-green.** The first Experiment 11 isomorph control was
  reverse-engineered to a target periodic ciphertext, so its "Vigenere" and
  "autokey" fixtures decoded to BYTE-IDENTICAL constant-period blocks and the
  detector's "period found" was trivially true. `make check` and codex review
  both passed it; only spot-reading the construction and noticing the two
  "different cipher" fixtures were identical caught it. Mitigation: for any
  control/null, spot-read that the signal is not trivially constructed, that two
  "different" fixtures are not secretly identical, and that the measured
  statistic is computed from data rather than asserted from the construction.
  Redesigned in commit `5af6b51`; the genuine control recovers a real Kasiski
  period and is honest that it uses period-aligned planted repeats.

---

## 6. Work queue (prioritized; pull from the top)

For each, read its full spec in `research/05-code-investigations.md`. Definition of
done for ALL: gate-green, the relevant null/control present (not just the point
estimate), honest interpretation in code/CLI docs, committed, progress logged.

> **STATUS (2026-06-22): QUEUE EXHAUSTED.** Items 1–7 below (Experiments 2, 11, 4,
> 5, 7, 8, 12) are all implemented, verified, reviewed, and committed — see §3 and
> the §9 progress log. Item 8 (Experiments 9 & 10) remains out of pure-crate scope
> as documented. The **completeness pass has been run**: a read-only audit found
> the gate green, the shared anchors consistent across modules, every statistic
> backed by a null/control, and no source overstatement; the only gaps were
> documentation (README / AGENTS golden rule / this section / a results synthesis),
> now addressed. The items below are retained for historical context.

1. **Experiment 2 — generation-pipeline artifact null (HIGH; do first).** Implement
   the documented base-7/64-bit generator; reproduce the wiki worked example
   (`acf686745634505c` → the 22-value sequence) as a test. Then feed it
   **structure-matched** random inputs (match per-message `[u32,u32]` block counts,
   output lengths, delimiter layout, the "no internal −1" property) and run the
   orders/null stats on the output. Question: does the base-7 pipeline *itself*
   tend to produce near-contiguous/bounded ranges or pseudo-isomorphs? If yes, the
   "encoding" reading weakens — a major correction. This is the deepest "is it
   meaningful vs. an artifact" test. (Unconstrained random ints are only a separate
   negative control, not the null.)

2. **Experiment 11 — positive controls on SOLVED Noita ciphers (HIGH).** Calibrate
   the tooling so a null on the eyes is meaningful. Matched controls: Common Glyphs
   (1:1 monoalphabetic → "SEEK THE END") for the frequency/substitution path;
   *generated* polyalphabetic/autokey fixtures with known keys for the
   isomorph/chaining path. Do NOT treat the Cessation Cipher as a tooling control
   (it's a multi-step image/key puzzle). If matched controls fail, the methodology
   is suspect.

3. **Experiment 4 — frequency/entropy/IoC across orders (MED).** Add chi-square
   goodness-of-fit to `analysis.rs`; run unigram freq + IoC on the 83-symbol
   alphabet for the honeycomb order AND raw/alternative orders to quantify how
   order-dependent flatness is. Community ref: IoC ~1.066, mean freq ~12.48.
   Interpret skeptically: flat freq rules monoalphabetic OUT; it does not rule a
   real message IN.

4. **Experiment 5 — periodicity/autocorrelation (MED).** Kasiski/autocorrelation/
   IoC-by-period over the 0–82 stream; brute Caesar + short Vigenère keys scored
   against **English AND Finnish** n-gram models (language unknown; add small
   corpora under `research/data/`). Expect no dominant period / no readable output;
   a positive must be triple-checked against Exp 0 integrity before any claim.

5. **Experiment 7 — isomorph detection WITH a shuffle null (MED-HIGH).** Detection
   exists upstream; the *null* is the missing contribution. Locate repeated
   relative-pattern segments across the 9 sequences; build a Monte-Carlo
   shuffle null (how often do isomorphs of the observed length appear in shuffled
   data of same alphabet/length?). Then confirm alphabet-chaining fails for a
   structural reason — run synthetic controls where chaining is *known* to succeed
   and *known* to fail, and check the eyes match the known-fail signature, not
   merely that it "failed".

6. **Experiment 8 — base-N/grouping reinterpretation (MED).** Compare single-glyph
   base-5 / trigram base-5 / engine base-7 / pairs / tetragrams by used-alphabet
   size and entropy vs candidate plaintext alphabets. Estimate internal state count
   *independently* (isomorph-length distribution / unicity distance) — don't assume
   83 (that risks circularity; 83 = alphabet size).

7. **Experiment 12 — candidate ciphers (LOWER; frontier, not verification).**
   Incrementing-wheel (ngraham20), Chaocipher/Hutton, S_83 deck. Implement +
   inverse; score outputs against English/Finnish. Treat any "solution" without a
   fully reproducible method as NOT credible.

8. **Experiments 9 & 10 (OUT of pure-crate scope; document, don't force).**
   Seed-invariance needs the game/world-gen PRNG; sprite-state clustering is image
   work (better as a small Python side-tool). The crate can still *store* cross-seed
   transcriptions and diff them. Skip unless you can do them cleanly std-only.
   - **Primary-observer update (2026-06-22):** the repo owner confirmed by direct
     in-game observation that (a) eye-message **content is identical across multiple
     world seeds** (Exp 9 — qualitative corroboration of seed-invariance; a vendored
     byte-for-byte cross-seed diff is still the stronger form and stays the one
     std-clean task worth doing here once a second-seed transcription exists), and
     (b) there are exactly **5 visually distinct orientations** (Exp 10 count), with
     the digit→direction labeling agreed to be an **arbitrary convention** — which is
     cryptanalytically immaterial since all stats run on the Exp-0-verified integer
     digit sequence, not the direction names. Recorded in `research/03` §§3–4 and
     `research/05` Exp 9/10. No code change; nothing in the conclusions moves.

When the queue is done: run a **completeness pass** — what's still asserted but
unverified? what null is still missing? Add those as new queue items and continue.

---

## 7. Verified data sources (already vendored; re-fetch only if needed)

- In-repo ground truth: `research/data/eye-messages/` (`ng_eyes.json` = ngraham20
  transcription; `xk_eye.php` = Xkeeper0 engine transcoder). Prefer these over the
  network.
- Upstream URLs (network = GitHub reachable; crates.io NOT): ngraham20
  `NoitaCryptographyResearch` (`eye/eyes.json`), Xkeeper0 gist
  `a6eda18571ef889be291822c400cc6c8`, ToboterXP `EyeGlyphs` (trigram-order
  bruteforce + English/Finnish corpora), CodeWarrior0 `noita-eye-glyph-analyses`,
  primary Google Doc `1s6gxrc1iLJ78iFfqC2d4qpB9_r_c5U5KwoHVYFFrjy0`, wiki
  `noita.wiki.gg/wiki/Eye_Messages`. Full list in `research/06-sources.md`.

---

## 8. Commands

```sh
make verify          # correctness gate: fmt + clippy(-D) + tests + rustdoc(-D) + cargo-deny
make check           # verify + machete + codespell + shellcheck + release build (full CI)
make setup           # install pre-commit hook
cargo test --locked  # authoritative test signal (use after each codex run)
cargo run -- orders                          # per-order structural stats
cargo run -- nulltest --seed 12345 --trials 1000   # the multiple-comparisons null
```

---

## 9. Progress log (append one line per completed item; newest last)

- 2026-06-22: Exp 0, 3, 1A, 1B done + review/P3 fix (commits ac0bcd7→2bdb0c0). Handoff written.
<!-- next agent: append `- <date>: <experiment> — <result + commit sha>` here as you finish each item -->
- 2026-06-22: Experiment 2 (generation-pipeline artifact null) — base-7 pipeline does not manufacture bounded 0..=82 contiguity; negative control only shows authored 0..=5 storage alphabet, not a message claim (commit 6f4ef3d).
- 2026-06-22: Experiment 2 review fixes — unbiased matched-length sampler + honest analytic no-`-1` rate (commit 24df29d).
- 2026-06-22: Experiment 11 (monoalphabetic positive control) — deterministic 1:1 substitution control preserves IoC/frequency multisets and recovers known-key plaintext without eye-message claims (commit 128c10c).
- 2026-06-22: Experiment 11 (isomorph/polyalphabetic positive control) — first-occurrence signature detector fires on short-key Vigenere/autokey fixtures and stays quiet on the full-length running-key contrast (commit ee87dfb).
- 2026-06-22: Experiment 11 isomorph control redesigned — Vigenere key-period recovery with period-aligned planted repeats vs Kasiski-resistant autokey/running-key (commit 5af6b51).
- 2026-06-22: Experiment 11 isomorph control — honest disclosure that the Kasiski signal uses period-aligned planted repeats (commit 6f7a2c).
- 2026-06-22: Experiment 4 (frequency/entropy/IoC across orders) — honeycomb winner is the only standard36 order fully inside 0..=82 (mean 12.48, x83/all 1.066, chi2=150.355); raw/order variants leave the 83-symbol support (commit 506b004).
- 2026-06-22: Experiment 5A (periodicity/autocorrelation battery) — no pooled or per-message period/lag clears the sampled report-wide random-null envelope; Kasiski repeats stop at bigrams (commit 1c6bbf8).
- 2026-06-22: Experiment 5A interpretation fixes — verdict derived from null-envelope flags + explicit Experiment 1B distance-4 reconciliation (commit 8891ebf).
- 2026-06-22: Experiment 5B-1 (English/Finnish n-gram language scorer) — held-out bigram MLL discriminates English -2.543859 vs Finnish-model -3.271251, Finnish -2.686381 vs English-model -3.187117 (commit 9e67f13).
- 2026-06-22: Experiment 7A (isomorph shuffle null) — real eyes do not exceed their within-message shuffle null for k=3..=8 repeated-signature kind counts (commit 6ed61c318fb040ab2a25bc627bd2e7e30b69244b).
- 2026-06-22: Experiment 7B (alphabet-chaining fail-signature) — eyes match the known-fail chaining signature across p=2..=16 under standard36-u012-d012, not the known-succeed Vigenere band (commit 3db4609626212d20827e46c6d466b5a88637bd9c).
- 2026-06-22: Experiment 8 (base-N grouping + independent state-count) — pairs are the nearest Latin-sized grouping but not entropy-compatible as raw plaintext; collision estimate 73..90 states overlaps 83 (commit 9c0372fa8e7ff52e489bc0f0334ee1978d3fecb0).
- 2026-06-22: Experiment 12 (candidate ciphers + Caesar/Vigenere brute vs English/Finnish) — candidate scores are mapping-conditioned; 256-trial shuffle null shows only pointwise tail rows under guessed mappings, the harness positive-control recovers Caesar/Vigenere plants, and no credible solution is established (commit 8bc7bdf0cf401a76709f98b118b2a141d6089be0).
- 2026-06-22: Experiment 12 interpretation rigor — pointwise tails now report the derived exceedance-rate diagnosis and eye-vs-plant effect-size contrast, keeping the result a clean negative rather than near-hits (commit b465dd3f182d076994dcbd1ee8442e1354f4f6a9).
- 2026-06-22: Experiments 9 & 10 primary-observer report (repo owner, direct in-game observation) — content identical across multiple seeds (qualitative seed-invariance corroboration; byte-for-byte cross-seed diff still pending) and exactly 5 visually distinct orientations with the digit→direction labeling agreed arbitrary (cryptanalytically immaterial; stats run on the Exp-0-verified integer sequence). Docs-only update to research/03 §§3–4, research/05 Exp 9/10, and §6 item 8; no code change, conclusions unchanged.
