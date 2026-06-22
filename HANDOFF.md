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

Modules: `glyph.rs` (Orientation 0–4 + delimiter; StorageSymbol −1..5; generic
Glyph/Alphabet), `trigram.rs` (reading layer 0–124), `corpus.rs`, `analysis.rs`
(frequencies/entropy/IoC/ngrams), `orders.rs`, `null.rs`, `main.rs` (CLI:
`demo`, `stats`, `orders`, `nulltest`).

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

---

## 6. Work queue (prioritized; pull from the top)

For each, read its full spec in `research/05-code-investigations.md`. Definition of
done for ALL: gate-green, the relevant null/control present (not just the point
estimate), honest interpretation in code/CLI docs, committed, progress logged.

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
